#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "../include/DNS.h"
#include "../include/cJSON.h"
#include "../include/DNSio.h"

#define MAX_BUFFER_SIZE 512
#define LISTEN_PORT 53
#define MAX_RR_NUM 100

void parseHeader(DNS_Header *header)
{
    header->id = ntohs(header->id);
    header->flags = ntohs(header->flags);
    header->queryNum = ntohs(header->queryNum);
    header->answerNum = ntohs(header->answerNum);
    header->authorNum = ntohs(header->authorNum);
    header->addNum = ntohs(header->addNum);
}

DNS_Query *getBufferQuery(char *buf, int buflen)
{
    DNS_Query *query = malloc(sizeof(DNS_Query));
    memcpy(&(query->qclass), buf + buflen - 2, 2);
    memcpy(&(query->qtype), buf + buflen - 4, 2);
    query->qclass = ntohs(query->qclass);
    query->qtype = ntohs(query->qtype);
    query->name = malloc((buflen - 12 - 4 + 1) * sizeof(char));
    memset(query->name, 0, buflen - 12 - 4 + 1);
    memcpy(query->name, buf + 12, buflen - 12 - 4);
    query->name = dns_format_to_domain(query->name);
    return query;
}

int main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);

    // 绑定地址和端口
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LISTEN_PORT);
    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    while (1)
    {
        printf("waiting for query\n");
        char buf[MAX_BUFFER_SIZE];
        socklen_t client_addr_len = sizeof(client_addr);
        int buflen = recvfrom(server_socket, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        if (buflen <= 12)
            continue;
        DNS_Header *recvheader = malloc(sizeof(DNS_Header));
        memcpy(recvheader, buf, sizeof(DNS_Header));
        printf("buflen:%d\n", buflen);
        parseHeader(recvheader);
        printf("%u %u %u %u %u %u\n", recvheader->id, recvheader->flags, recvheader->queryNum, recvheader->answerNum, recvheader->authorNum, recvheader->addNum);
        uint16_t flagcheck = 0xF800;
        printf("flag:%u\n", recvheader->flags);
        // 检查查询和OPCODE
        if ((ntohs(recvheader->flags) & flagcheck) != 0x0000)
        {
            DNS_Header *errheader = generateHeader(R, QUERY, 1, 1, 0, 0, 0, 0, 0, recvheader->id);
            sendto(server_socket, errheader, sizeof(DNS_Header), 0, (struct sockaddr *)&client_addr, client_addr_len);
            printf("flags error\n");
            continue;
        }
        // 检查查询数量
        if (recvheader->queryNum != 1)
        {
            DNS_Header *errheader = generateHeader(R, QUERY, 1, 1, 0, 0, 0, 0, 0, recvheader->id);
            sendto(server_socket, errheader, sizeof(DNS_Header), 0, (struct sockaddr *)&client_addr, client_addr_len);
            printf("queryNum error\n");
            continue;
        }
        if ((recvheader->queryNum == 1) && (recvheader->addNum == 0) && (recvheader->answerNum == 0) && (recvheader->authorNum == 0))
        {
            DNS_Query *recvquery = getBufferQuery(buf, buflen);
            cJSON *rrJSONarray = readRRArray();
            printf("name:%s\n", recvquery->name);
            printf("qtype:%d\n", recvquery->qtype);
            char *tempname = strdup(recvquery->name);
            cJSON *resultArray = getResultArraybyName(rrJSONarray, tempname, recvquery->qtype);
            printf("resultArray size:%d\n", cJSON_GetArraySize(resultArray));
            if (cJSON_GetArraySize(resultArray) == 0)
            {
                // 开始进行迭代查询
            }
            else
            {
                // 使用本地cache进行回答
                int answerNum = cJSON_GetArraySize(resultArray);
                DNS_RR *answerRR = praseResult(resultArray);
                char sendbuf[MAX_BUFFER_SIZE];
                DNS_Header *sendheader = generateHeader(R, QUERY, 1, 0, 0, 1, answerNum, 0, 0, recvheader->id);
                memcpy(sendbuf, sendheader, sizeof(DNS_Header));
                memcpy(sendbuf + sizeof(DNS_Header), buf + sizeof(DNS_Header), buflen - sizeof(DNS_Header));
                int index = buflen;
                switch (recvquery->qtype)
                {
                case CNAME:
                {
                    for (int i = 0; i < answerNum; i++)
                    {
                        printf("cname\n");
                        uint16_t name = htons(0xc00c);
                        answerRR[i].ttl = htonl(answerRR[i].ttl);
                        answerRR[i]._class = htons(answerRR[i]._class);
                        answerRR[i].type = htons(answerRR[i].type);
                        answerRR[i].rdata = domain_to_dns_format(answerRR[i].rdata);
                        answerRR[i].data_len = htons(strlen(answerRR[i].rdata)+1);
                        memcpy(sendbuf + index, &name, 2);
                        index += 2;
                        memcpy(sendbuf + index, &(answerRR[i].type), 2);
                        index += 2;
                        memcpy(sendbuf + index, &answerRR[i]._class, 2);
                        index += 2;
                        memcpy(sendbuf + index, &answerRR[i].ttl, 4);
                        index += 4;
                        memcpy(sendbuf + index, &answerRR[i].data_len, 2);
                        index += 2;
                        memcpy(sendbuf + index, answerRR[i].rdata, strlen(answerRR[i].rdata)+1);
                        index += strlen(answerRR[i].rdata)+1;
                    }
                    break;
                }
                case A:{
                    for (int i = 0; i < answerNum; i++)
                    {
                        uint16_t name = htons(0xc00c);
                        answerRR[i].ttl = htonl(answerRR[i].ttl);
                        answerRR[i]._class = htons(answerRR[i]._class);
                        answerRR[i].type = htons(answerRR[i].type);
                        answerRR[i].data_len = htons(answerRR[i].data_len);
                        memcpy(sendbuf + index, &name, 2);
                        index += 2;
                        memcpy(sendbuf + index, &(answerRR[i].type), 2);
                        index += 2;
                        memcpy(sendbuf + index, &(answerRR[i]._class), 2);
                        index += 2;
                        memcpy(sendbuf + index, &(answerRR[i].ttl), 4);
                        index += 4;
                        memcpy(sendbuf + index, &(answerRR[i].data_len), 2);
                        index += 2;
                        memcpy(sendbuf + index, (answerRR[i].rdata), 4);
                        index += 4;
                    }
                    break;
                }
                case MX:{
                    for (int i = 0; i < answerNum; i++)
                    {
                        uint16_t name = htons(0xc00c);
                        answerRR[i].ttl = htonl(answerRR[i].ttl);
                        answerRR[i]._class = htons(answerRR[i]._class);
                        answerRR[i].type = htons(answerRR[i].type);
                        char* preferencechar = (char*)malloc(3);
                        memcpy(preferencechar, answerRR[i].rdata, 2);
                        preferencechar[2] = '\0';
                        uint16_t preference = atoi(preferencechar);
                        preference = htons(preference);
                        char* exchange = domain_to_dns_format(answerRR[i].rdata+2);
                        answerRR[i].data_len = htons(strlen(exchange)+3);
                        memcpy(sendbuf + index, &name, 2);
                        index += 2;
                        memcpy(sendbuf + index, &(answerRR[i].type), 2);
                        index += 2;
                        memcpy(sendbuf + index, &(answerRR[i]._class), 2);
                        index += 2;
                        memcpy(sendbuf + index, &(answerRR[i].ttl), 4);
                        index += 4;
                        memcpy(sendbuf + index, &(answerRR[i].data_len), 2);
                        index += 2;
                        memcpy(sendbuf + index, &preference, 2);
                        index += 2;
                        memcpy(sendbuf + index, exchange, strlen(exchange)+1);
                        index += strlen(exchange)+1;
                    }
                    break;
                }
                }
                sendto(server_socket, sendbuf, index, 0, (struct sockaddr *)&client_addr, client_addr_len);
            }
        }
    }
    close(server_socket);

    return 0;
}