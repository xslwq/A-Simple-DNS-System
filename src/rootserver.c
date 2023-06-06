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
#define ROOT_SERVER "127.0.0.2" // 根服务器地址
#define COM_SERVER "127.0.0.3"
#define EDU_SERVER "127.0.0.6"

int main()
{
    cJSON *rrJSONarray = readRRArray("../data/rootRR.json");
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ROOT_SERVER);
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
        ssize_t recvlen = recv(client_socket, buf, MAX_BUFFER_SIZE, 0) - 2;
        printf("1");
        DNS_Header *header = malloc(sizeof(DNS_Header));
        memcpy(header, buf + 2, 12);
        header->id = ntohs(header->id);
        printf("1");
        DNS_Query *query = malloc(sizeof(DNS_Query));
        memcpy(&(query->qclass), buf + recvlen - 2, 2);
        memcpy(&(query->qtype), buf + recvlen - 4, 2);
        query->qclass = ntohs(query->qclass);
        query->qtype = ntohs(query->qtype);
        printf("1");
        query->name = malloc((recvlen - 12 - 6 + 2) * sizeof(char));
        memset(query->name, 0, recvlen - 12 - 6 + 2);
        memcpy(query->name, buf + 14, recvlen - 12 - 5);
        printf("Query: %s\n", query->name);
        query->name = dns_format_to_domain(query->name);
        printf("Query: %s\n", query->name);
        char *suffix = strrchr(query->name, '.');
        recvlen += 2;
        if (suffix != NULL)
        {
            if (strcmp(suffix, ".com") == 0)
            {
                char sendbuf[MAX_BUFFER_SIZE];
                cJSON *com = getResultArraybyName(rrJSONarray, ".com", NS);
                DNS_RR *comrr = praseResult(com);
                DNS_Header *comheader = generateHeader(R, QUERY, 1, 0, 0, 1, 1, 0, 1, header->id);
                memcpy(sendbuf, buf, recvlen);
                memcpy(sendbuf+2, comheader, 12);
                uint16_t name = htons(0xc00c);
                memcpy(sendbuf+recvlen, &name, 2);
                comrr->type = htons(comrr->type);
                memcpy(sendbuf+recvlen+2, &(comrr->type), 2);
                comrr->_class = htons(comrr->_class);
                memcpy(sendbuf+recvlen+4, &(comrr->_class), 2);
                comrr->ttl = htonl(comrr->ttl);
                memcpy(sendbuf+recvlen+6, &(comrr->ttl), 4);
                printf("rdata: %s\n", comrr->rdata);
                printf("rdatalen: %ld\n", strlen(comrr->rdata));
                comrr->rdata=domain_to_dns_format(comrr->rdata);
                printf("rdata: %s\n", comrr->rdata);
                printf("rdatalen: %ld\n", strlen(comrr->rdata));
                comrr->data_len = htons(strlen(comrr->rdata)+1);
                memcpy(sendbuf+recvlen+10, &(comrr->data_len), 2);
                memcpy(sendbuf+recvlen+12, comrr->rdata, strlen(comrr->rdata)+1);
                int compptr = recvlen+12;
                int ptr = recvlen+12+strlen(comrr->rdata)+1;
                printf("ptr: %d\n", ptr);


                char *comservername= strdup(comrr[0].rdata);
                cJSON *comA = getResultArraybyName(rrJSONarray, "dns.comserver.net", A); // 从json中获取com服务器的A记录
                printf("array size: %d\n", cJSON_GetArraySize(comA));
                cJSON_Delete(comA);
                //DNS_RR *comArr = praseResult(comA);
                DNS_RR* comArr = malloc(sizeof(DNS_RR));
                name = htons(0xc000+compptr-2);
                uint32_t comip = inet_addr(COM_SERVER);
                comArr->type = htons(A);
                comArr->_class = htons(IN);
                comArr->ttl = htonl(10000000);
                comArr->data_len = htons(4);

                memcpy(sendbuf+ptr, &name, 2);
                memcpy(sendbuf+ptr+2, &comArr->type, 2);
                memcpy(sendbuf+ptr+4, &comArr->_class, 2);
                memcpy(sendbuf+ptr+6, &comArr->ttl, 4);
                memcpy(sendbuf+ptr+10, &comArr->data_len, 2);
                memcpy(sendbuf+ptr+12, &comip, 4);
                uint16_t length = ptr+14;
                length = htons(length);
                memcpy(sendbuf, &length, 2);
                send(client_socket, sendbuf, ptr+16, 0);
                free(comheader);
                free(comrr);
                free(comservername);
                free(comArr);

            }
            else if (strcmp(suffix, ".edu") == 0)
            {
                char sendbuf[MAX_BUFFER_SIZE];
                cJSON *com = getResultArraybyName(rrJSONarray, ".edu", NS);
                DNS_RR *comrr = praseResult(com);
                DNS_Header *comheader = generateHeader(R, QUERY, 1, 0, 0, 1, 2, 0, 0, header->id);
                memcpy(sendbuf, buf, recvlen);
                memcpy(sendbuf+2, comheader, 12);
                uint16_t name = htons(0xc00c);
                memcpy(sendbuf+recvlen, &name, 2);
                comrr->type = htons(comrr->type);
                memcpy(sendbuf+recvlen+2, &(comrr->type), 2);
                comrr->_class = htons(comrr->_class);
                memcpy(sendbuf+recvlen+4, &(comrr->_class), 2);
                comrr->ttl = htonl(comrr->ttl);
                memcpy(sendbuf+recvlen+6, &(comrr->ttl), 4);
                printf("rdata: %s\n", comrr->rdata);
                printf("rdatalen: %ld\n", strlen(comrr->rdata));
                comrr->rdata=domain_to_dns_format(comrr->rdata);
                printf("rdata: %s\n", comrr->rdata);
                printf("rdatalen: %ld\n", strlen(comrr->rdata));
                comrr->data_len = htons(strlen(comrr->rdata)+1);
                memcpy(sendbuf+recvlen+10, &(comrr->data_len), 2);
                memcpy(sendbuf+recvlen+12, comrr->rdata, strlen(comrr->rdata)+1);
                int compptr = recvlen+12;
                int ptr = recvlen+12+strlen(comrr->rdata)+1;
                printf("ptr: %d\n", ptr);


                char *comservername= strdup(comrr[0].rdata);
                cJSON *comA = getResultArraybyName(rrJSONarray, "dns.eduserver.net", A); // 从json中获取edu服务器的A记录
                printf("array size: %d\n", cJSON_GetArraySize(comA));
                cJSON_Delete(comA);
                //DNS_RR *comArr = praseResult(comA);
                DNS_RR* comArr = malloc(sizeof(DNS_RR));
                name = htons(0xc000+compptr-2);
                uint32_t comip = inet_addr(EDU_SERVER);
                comArr->type = htons(A);
                comArr->_class = htons(IN);
                comArr->ttl = htonl(10000000);
                comArr->data_len = htons(4);

                memcpy(sendbuf+ptr, &name, 2);
                memcpy(sendbuf+ptr+2, &comArr->type, 2);
                memcpy(sendbuf+ptr+4, &comArr->_class, 2);
                memcpy(sendbuf+ptr+6, &comArr->ttl, 4);
                memcpy(sendbuf+ptr+10, &comArr->data_len, 2);
                memcpy(sendbuf+ptr+12, &comip, 4);
                uint16_t length = ptr+14;
                length = htons(length);
                memcpy(sendbuf, &length, 2);
                send(client_socket, sendbuf, ptr+16, 0);
                free(comheader);
                free(comrr);
                free(comservername);
                free(comArr);
            }
            else
            {
                printf("not supported\n");
                char sendbuf[MAX_BUFFER_SIZE];
                DNS_Header *errheader = generateHeader(R, QUERY, 1, 4, 0, 0, 0, 0, 0, header->id);
                uint16_t length = 12;
                length = htons(length);
                memcpy(sendbuf, &length, 2);
                memcpy(sendbuf + 2, errheader, 12);
                send(client_socket, sendbuf, 14, 0);
                free(errheader);
            }
            free(query->name);
            free(header);
            free(query);
        }

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
