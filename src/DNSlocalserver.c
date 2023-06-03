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
    cJSON *rrJSONarray = NULL;

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
            printf("recvquery->name:%s\n", recvquery->name);
            cJSON *resultArray = getResultArraybyName(rrJSONarray, recvquery->name);
            if (resultArray == NULL)
            {
                // 开始进行迭代查询
            }
            else
            {
                // 使用本地cache进行回答
                int resultArraySize = cJSON_GetArraySize(resultArray);
                DNS_RR *resultRRArrays = malloc(resultArraySize * sizeof(DNS_RR));
                
            }
        }
    }
    close(server_socket);

    return 0;
}