#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "../include/DNSio.h"
#include "../include/DNS.h"

#define MAX_BUFFER_SIZE 512
#define LISTEN_PORT 53
#define BUPT_COM_SERVER "127.0.0.5"

int main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(BUPT_COM_SERVER);
    server_addr.sin_port = htons(LISTEN_PORT);
    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_socket, 5);
    while (1)
    {
        // 等待客户端连接请求
        printf("Waiting for connection...\n");
        socklen_t client_addr_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0)
        {
            perror("accept error");
            exit(EXIT_FAILURE);
        }

        // 接收客户端数据报文
        char buf[MAX_BUFFER_SIZE];
        ssize_t recvlen = recv(client_socket, buf, MAX_BUFFER_SIZE, 0);
        DNS_Header *header = malloc(sizeof(DNS_Header));
        memcpy(header, buf + 2, 12);
        // 解析查询报文
        DNS_Query *query = malloc(sizeof(DNS_Query));
        memcpy(&(query->qclass), buf + recvlen - 2, 2);
        memcpy(&(query->qtype), buf + recvlen - 4, 2);
        query->qclass = ntohs(query->qclass);
        printf("qtype: %d\n", query->qtype);
        query->qtype = ntohs(query->qtype);
        query->name = malloc((recvlen - 12 - 6 + 2) * sizeof(char));
        memset(query->name, 0, recvlen - 12 - 6 + 2);
        memcpy(query->name, buf + 14, recvlen - 12 - 5);
        query->name = dns_format_to_domain(query->name);
        parseHeader(header);
        printf("query name: %s\n", query->name);
        printf("query type: %d\n", query->qtype);
        // 读取json文件
        cJSON *rrJSONarray = readRRArray("../data/buptcomRR.json");
        cJSON *answer = getResultArraybyName(rrJSONarray, query->name, query->qtype);
        DNS_RR *answerRR = praseResult(answer);
        int answerNum = cJSON_GetArraySize(answer);
        printf("answerNum: %d\n", answerNum);
        if (answerNum == 0)
        {
            char sendbuf[MAX_BUFFER_SIZE];
            DNS_Header *errheader = generateHeader(R, QUERY, 1, 4, 0, 0, 0, 0, 0, header->id);
            uint16_t length = 12;
            length = htons(length);
            memcpy(sendbuf, &length, 2);
            memcpy(sendbuf + 2, errheader, 12);
            send(client_socket, sendbuf, 14, 0);
            free(errheader);
            continue;
        }
        char sendbuf[MAX_BUFFER_SIZE];
        DNS_Header *sendheader = generateHeader(R, QUERY, 1, 0, 0, 1, answerNum, 0, 0, header->id);
        memcpy(sendbuf + 2, sendheader, sizeof(DNS_Header));
        memcpy(sendbuf + sizeof(DNS_Header) + 2, buf + sizeof(DNS_Header) + 2, recvlen - sizeof(DNS_Header) - 2);
        int index = recvlen;
        switch (query->qtype)//根据查询类型填充回答区
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
            uint16_t length = htons(index - 2);
            memcpy(sendbuf, &length, 2);
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
            uint16_t length = htons(index - 2);
            memcpy(sendbuf, &length, 2);
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
            for (int i = 0; i < answerNum; i++)
            {
                char *tempname1 = strdup(answerRR[i].rdata + 2);
                cJSON *rrJSONarray = readRRArray("../data/buptcomRR.json");
                cJSON *additional = getResultArraybyName(rrJSONarray, tempname1, 1);
                DNS_RR *additionalRR = praseResult(additional);
                printf("arraysize:%d\n", cJSON_GetArraySize(additional));
                additionalRR[i].ttl = htonl(additionalRR[i].ttl);
                additionalRR[i]._class = htons(additionalRR[i]._class);
                additionalRR[i].type = htons(additionalRR[i].type);
                additionalRR[i].data_len = htons(additionalRR[i].data_len);
                uint16_t name = htons(0xc000 + compptr[i]-2);
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
                sendbuf[13] += 1;
            }
            uint16_t length = htons(index - 2);
            memcpy(sendbuf, &length, 2);
            break;
        }
        }
        send(client_socket, sendbuf, index, 0);

        free(query->name);
        free(header);
        free(query);

        if (listen(server_socket, 5) < 0)
        {
            perror("listen error");
            exit(EXIT_FAILURE);
        }
    }

    // 关闭服务器套接字
    close(server_socket);

    return 0;
}