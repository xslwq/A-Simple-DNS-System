#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "../include/DNS.h"
#include "../include/cJSON.h"
#include "../include/DNSio.h"

#define MAX_BUFFER_SIZE 512
#define LISTEN_PORT 53
#define MAX_RR_NUM 100           // 最大缓存条目数
#define ROOT_SERVER "127.0.0.2"  // 根服务器地址
#define LOCAL_SERVER "127.0.0.1" // 本地服务器地址
#define ROOT_SERVER_PORT 53
#define TIME_OUT 3 // 超时时间
#define CACHE_ENABLE 1

// 解析buffer中的DNS报头
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
    cJSON *rrJSONarray = readRRArray("../data/RR.json");

    // 绑定地址和端口
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(LOCAL_SERVER);
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
        parseHeader(recvheader);
        uint16_t flagcheck = 0xF800;
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
        // 检查回答数量
        if ((recvheader->queryNum == 1) && (recvheader->addNum == 0) && (recvheader->answerNum == 0) && (recvheader->authorNum == 0))
        {
            int connectclosed = 0;
            DNS_Query *recvquery = getBufferQuery(buf, buflen);
            if (recvquery->qtype != A && recvquery->qtype != CNAME && recvquery->qtype != MX)
            {
                DNS_Header *errheader = generateHeader(R, QUERY, 1, 4, 0, 0, 0, 0, 0, recvheader->id);
                sendto(server_socket, errheader, sizeof(DNS_Header), 0, (struct sockaddr *)&client_addr, client_addr_len);
                printf("type not support\n");
                continue;
            }
            cJSON *resultArray = getResultArraybyName(rrJSONarray, recvquery->name, recvquery->qtype);
            if (cJSON_GetArraySize(resultArray) == 0)
            {
                // 开始进行迭代查询
                printf("start iteration\n");
                char sendbuf[MAX_BUFFER_SIZE];
                uint16_t itrid = generateID();
                uint16_t msglen = htons(buflen);
                memcpy(sendbuf, &msglen, 2);
                memcpy(sendbuf + 2, buf, buflen);
                memcpy(sendbuf + 2, &itrid, 2);
                struct sockaddr_in root_addr;
                root_addr.sin_family = AF_INET;
                root_addr.sin_addr.s_addr = inet_addr(ROOT_SERVER);
                root_addr.sin_port = htons(ROOT_SERVER_PORT);
                int recvlen = 0;
                char recvbuf[MAX_BUFFER_SIZE];
                while (1)
                {
                    int sendfd = socket(AF_INET, SOCK_STREAM, 0);
                    int ret = connect(sendfd, (struct sockaddr *)&root_addr, sizeof(root_addr));
                    if (ret < 0)
                    {
                        perror("can't make connection with server");
                        connectclosed = 1;
                        break;
                    }
                    uint16_t id = generateID();
                    memcpy(sendbuf + 2, &id, 2);
                    if (send(sendfd, sendbuf, buflen + 2, 0) < 0)
                    {
                        perror("send error");
                        connectclosed = 1;
                        break;
                    }
                    // 设置超时时间
                    struct timeval timeout;
                    timeout.tv_sec = TIME_OUT;
                    timeout.tv_usec = 0;
                    setsockopt(sendfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    memset(recvbuf, 0, sizeof(recvbuf));
                    int recvlen = recv(sendfd, recvbuf, sizeof(recvbuf), 0);
                    close(sendfd);
                    DNS_Header *iterecvheader = malloc(sizeof(DNS_Header));
                    memcpy(iterecvheader, recvbuf + 2, sizeof(DNS_Header));
                    parseHeader(iterecvheader);
                    if ((iterecvheader->flags & 0x0F) == 4)
                    {
                        DNS_Header *errheader = generateHeader(R, QUERY, 1, 4, 0, 0, 0, 0, 0, recvheader->id);
                        sendto(server_socket, errheader, sizeof(DNS_Header), 0, (struct sockaddr *)&client_addr, client_addr_len);
                        connectclosed = 1;
                        printf("name server: type not support\n");
                        break;
                    }
                    int ptr = buflen + 2;
                    DNS_RR *nsRR = malloc(sizeof(DNS_RR));
                    char *name = dealCompressPointer(recvbuf, ptr);
                    nsRR->name = name;
                    ptr += 2;
                    memcpy(&(nsRR->type), recvbuf + ptr, 2);
                    nsRR->type = ntohs(nsRR->type);
                    ptr += 2;
                    memcpy(&(nsRR->_class), recvbuf + ptr, 2);
                    ptr += 2;
                    memcpy(&(nsRR->ttl), recvbuf + ptr, 4);
                    ptr += 4;
                    memcpy(&(nsRR->data_len), recvbuf + ptr, 2);
                    ptr += 2;
                    ptr += nsRR->data_len;
                    char ipv[4];
                    ptr += 12;
                    // 检查迭代查询的回答数量
                    if (iterecvheader->answerNum == 1 && (iterecvheader->addNum == 0 || (nsRR->type == MX && iterecvheader->addNum == 1)))
                    {
                        char sendbuffer[MAX_BUFFER_SIZE];
                        memcpy(sendbuffer, recvbuf + 2, recvlen - 2);
                        recvheader->id = htons(recvheader->id);
                        memcpy(sendbuffer, &(recvheader->id), 2);
                        sendto(server_socket, sendbuffer, recvlen - 2, 0, (struct sockaddr *)&client_addr, client_addr_len);
                        if (CACHE_ENABLE)
                        {
                            DNS_RR *cache = malloc(sizeof(DNS_RR));
                            
                        }
                        break;
                    }
                    // 返回查询结果
                    memcpy(ipv, recvbuf + recvlen - 4, 4);
                    char ip[16];
                    sprintf(ip, "%d.%d.%d.%d", ipv[0], ipv[1], ipv[2], ipv[3]);
                    printf("nextip: %s\n", ip);
                    root_addr.sin_addr.s_addr = inet_addr(ip);
                }
                if (connectclosed == 1)
                    continue;
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
                        uint16_t name = htons(0xc00c);
                        answerRR[i].ttl = htonl(answerRR[i].ttl);
                        answerRR[i]._class = htons(answerRR[i]._class);
                        answerRR[i].type = htons(answerRR[i].type);
                        answerRR[i].rdata = domain_to_dns_format(answerRR[i].rdata);
                        answerRR[i].data_len = htons(strlen(answerRR[i].rdata) + 1);
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
                        memcpy(sendbuf + index, answerRR[i].rdata, strlen(answerRR[i].rdata) + 1);
                        index += strlen(answerRR[i].rdata) + 1;
                    }
                    break;
                }
                case A:
                {
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
                case MX:
                {
                    int compptr[answerNum];
                    for (int i = 0; i < answerNum; i++)
                    {
                        uint16_t name = htons(0xc00c);
                        answerRR[i].ttl = htonl(answerRR[i].ttl);
                        answerRR[i]._class = htons(answerRR[i]._class);
                        answerRR[i].type = htons(answerRR[i].type);
                        char *preferencechar = (char *)malloc(3);
                        memcpy(preferencechar, answerRR[i].rdata, 2);
                        preferencechar[2] = '\0';
                        uint16_t preference = atoi(preferencechar);
                        preference = htons(preference);
                        char *exchange = domain_to_dns_format(answerRR[i].rdata + 2);
                        answerRR[i].data_len = htons(strlen(exchange) + 3);
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
                        memcpy(sendbuf + index, exchange, strlen(exchange) + 1);
                        compptr[i] = index;
                        index += strlen(exchange) + 1;
                    }
                    for (int i = 0; i < answerNum; i++)//对MX记录的附加部分进行处理
                    {
                        cJSON *rrJSONarray = readRRArray("../data/RR.json");
                        char *tempname1 = strdup(answerRR[i].rdata + 2);
                        cJSON *additional = getResultArraybyName(rrJSONarray, tempname1, 1);
                        cJSON *iter = NULL;
                        DNS_RR *additionalRR = praseResult(additional);
                        additionalRR[i].ttl = htonl(additionalRR[i].ttl);
                        additionalRR[i]._class = htons(additionalRR[i]._class);
                        additionalRR[i].type = htons(additionalRR[i].type);
                        additionalRR[i].data_len = htons(additionalRR[i].data_len);
                        uint16_t name = ntohs(0xc000 + compptr[i]);
                        memcpy(sendbuf + index, &name, 2);
                        index += 2;
                        memcpy(sendbuf + index, &(additionalRR[i].type), 2);
                        index += 2;
                        memcpy(sendbuf + index, &(additionalRR[i]._class), 2);
                        index += 2;
                        memcpy(sendbuf + index, &(additionalRR[i].ttl), 4);
                        index += 4;
                        memcpy(sendbuf + index, &(additionalRR[i].data_len), 2);
                        index += 2;
                        memcpy(sendbuf + index, (additionalRR[i].rdata), 4);
                        index += 4;
                        sendbuf[11] += 1;
                    }
                    break;
                }
                }
                sendto(server_socket, sendbuf, index, 0, (struct sockaddr *)&client_addr, client_addr_len);
                free(answerRR);
            }
        }
    }
    close(server_socket);

    return 0;
}