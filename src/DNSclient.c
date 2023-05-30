#include "../include/DNS.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>

#define RECV_BUF_SIZE 500             // 接收缓冲区大小
#define DEFAULT_SERVER "8.8.8.8"    // 默认DNS服务器地址
#define DNS_SERVER_PORT 53            // DNS服务器端口
#define TIMEOUT 5                     // 超时时间

DNS_RR *getRR(char *buf, int sendDataOffset, uint16_t awnserNum);
DNS_RR *recv_from_server(int sock, int sendDataOffset);
int client_to_server(const char *domain, DNS_QUERY_TYPE querytype);

int client_to_server(const char *domain, DNS_QUERY_TYPE querytype)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in DNShost;
    memset(&DNShost, 0, sizeof(DNShost));
    DNShost.sin_family = AF_INET;
    DNShost.sin_port = htons(DNS_SERVER_PORT);
    DNShost.sin_addr.s_addr = inet_addr(DEFAULT_SERVER);

    DNS_Header *header = generateHeader(Q, QUERY, 1, 0, 0, 1, 0, 0, 0,generateID()); // 报头参数：_QUERY类型,_操作码,_是否递归查询,_响应码,_是否截断,_问题数,_回答数,_授权数,_附加数
    DNS_Query *query = generateQuery(domain, querytype, IN);

    unsigned char *buf = (unsigned char *)malloc(sizeof(DNS_Header) + strlen((const char *)query->name) + 1 + sizeof(query->qtype) + sizeof(query->qclass));
    memcpy(buf, header, sizeof(DNS_Header));
    memcpy(buf + sizeof(DNS_Header), query->name, strlen(query->name) + 1);
    memcpy(buf + sizeof(DNS_Header) + strlen(query->name) + 1, &query->qtype, sizeof(query->qtype));
    memcpy(buf + sizeof(DNS_Header) + strlen(query->name) + 1 + sizeof(query->qtype), &query->qclass, sizeof(query->qclass));

    // 为什么这里不能使用sizeof(buf)=8？sizeof(*buf)=1也用不了？内存一共是31个字节。
    // 解决办法：将固定的字节常数写入一个int变量。
    int sendbufferlen = sizeof(DNS_Header) + strlen((const char *)query->name) + 1 + sizeof(query->qtype) + sizeof(query->qclass);
    int sent = sendto(sock, buf, sendbufferlen, 0, (struct sockaddr *)&DNShost, sizeof(DNShost));

    if (sent == -1)
    {
        perror("sendto");
        exit(1);
    }
    free(buf);
    return sock;
}

DNS_RR *recv_from_server(int sock, int sendDataOffset)
{
    char *recvbuf = (char *)malloc(RECV_BUF_SIZE);
    struct sockaddr_in DNShost;
    memset(&DNShost, 0, sizeof(DNShost));
    socklen_t len = sizeof(DNShost);

    //超时为5S
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int recvlen = recvfrom(sock, recvbuf, RECV_BUF_SIZE, 0, (struct sockaddr *)&DNShost, &len);

    if (recvlen < 0)
    {
        perror("recvfrom error,maybe timeout\n");
        exit(1);
    }
    DNS_Header recvheader;
    memcpy(&(recvheader.id), recvbuf, 2);
    memcpy(&(recvheader.flags), recvbuf + 2, 2);
    memcpy(&(recvheader.queryNum), recvbuf + 4, 2);
    memcpy(&(recvheader.answerNum), recvbuf + 6, 2);
    memcpy(&(recvheader.authorNum), recvbuf + 8, 2);
    memcpy(&(recvheader.addNum), recvbuf + 10, 2);
    recvheader.id = ntohs(recvheader.id);
    recvheader.flags = ntohs(recvheader.flags);
    recvheader.queryNum = ntohs(recvheader.queryNum);
    recvheader.answerNum = ntohs(recvheader.answerNum);
    recvheader.authorNum = ntohs(recvheader.authorNum);
    recvheader.addNum = ntohs(recvheader.addNum);
    isNOERROR(recvheader.flags);

    if (recvheader.answerNum != 0 && recvheader.authorNum == 0 && recvheader.addNum == 0)
    {
        DNS_RR *arrayRR = getRR(recvbuf, sendDataOffset, recvheader.answerNum);
        return arrayRR;
    }
    else
    {
        printf("packet error\n");
        exit(1);
    }
}

DNS_RR *getRR(char *buf, int sendDataOffset, uint16_t awnserNum)
{
    DNS_RR *arrayRR = (DNS_RR *)malloc(awnserNum * sizeof(DNS_RR));
    memset(arrayRR, 0, awnserNum * sizeof(DNS_RR));
    int ptr = sendDataOffset;
    int size = 0;
    uint16_t comp = (buf[ptr] << 8) | buf[ptr + 1];
    for (int i = 0; i < awnserNum; i++)
    {
        if ((comp & 0xc000) >> 14 != 0x03) // RR非压缩指针
        {
            size = 0;
            for (int j = ptr; buf[j] != 0; j++)
            {
                if (buf[j] == 0)
                    size = j - ptr + 1;
            }
            arrayRR[i].name = (char *)malloc(size * sizeof(char));
            memcpy(arrayRR[i].name, buf + ptr, size);
            arrayRR[i].name = (unsigned char *)dns_format_to_domain(arrayRR[i].name);
            memcpy(&(arrayRR[i].type), buf + ptr + size, 2);
            memcpy(&(arrayRR[i]._class), buf + ptr + size + 2, 2);
            memcpy(&(arrayRR[i].ttl), buf + ptr + size + 4, 4);
            memcpy(&(arrayRR[i].data_len), buf + ptr + size + 8, 2);
            arrayRR[i].type = ntohs(arrayRR[i].type);
            arrayRR[i]._class = ntohs(arrayRR[i]._class);
            arrayRR[i].ttl = ntohl(arrayRR[i].ttl);
            arrayRR[i].data_len = ntohs(arrayRR[i].data_len);
            ptr += size + 10;
        }
        else
        { // RR压缩指针
            size = 0;
            uint16_t compptr = ((buf[ptr] << 8) | buf[ptr + 1]) & 0x3fff;
            // printf("compptr:%u\n", compptr);
            for (int j = compptr;; j++)
            {
                if (buf[j] == 0)
                {
                    size = j - compptr + 1;
                    break;
                }
            }
            // printf("size:%d\n", size);
            arrayRR[i].name = (char *)malloc(size * sizeof(char));
            memcpy(arrayRR[i].name, buf + compptr, size);
            arrayRR[i].name = (unsigned char *)dns_format_to_domain(arrayRR[i].name);
            ptr += 2;
            memcpy(&(arrayRR[i].type), buf + ptr, 2);
            memcpy(&(arrayRR[i]._class), buf + ptr + 2, 2);
            memcpy(&(arrayRR[i].ttl), buf + ptr + 4, 4);
            memcpy(&(arrayRR[i].data_len), buf + ptr + 8, 2);
            arrayRR[i].type = ntohs(arrayRR[i].type);
            arrayRR[i]._class = ntohs(arrayRR[i]._class);
            arrayRR[i].ttl = ntohl(arrayRR[i].ttl);
            arrayRR[i].data_len = ntohs(arrayRR[i].data_len);
            ptr += 10;
            switch (arrayRR[i].type) // 目前只支持A、MX、CNAME
            {
            case A:
            {
                //bug:malloc: corrupted top size
                arrayRR[i].rdata = (unsigned char *)malloc(arrayRR[i].data_len * sizeof(char));
                memcpy(arrayRR[i].rdata, buf + ptr, arrayRR[i].data_len);
                ptr += arrayRR[i].data_len;
                printf("data_len1:%u\n", arrayRR[i].data_len);

                printf("Resource Record %d:\n", i + 1);
                printf(" name:%s\n", arrayRR[i].name);
                printf(" type:%s\n", querytypetoString(arrayRR[i].type));
                printf(" class:%u\n", arrayRR[i]._class);
                printf(" ttl:%u\n", arrayRR[i].ttl);
                printf(" data_len:%u\n", arrayRR[i].data_len);
                printf(" IPaddress:");
                int a[4]={0};
                for(int j = 0; j < arrayRR[i].data_len-1; j++)
                {
                    a[j] = arrayRR[i].rdata[j];
                }
                printf("%d.%d.%d.%d\n", a[0], a[1], a[2], a[3]);
                printf("\n");

                break;
            }
            case MX:
            {
                char *rdata = (char *)malloc(256 * sizeof(char));
                memcpy(rdata, buf + ptr, 2);
                ptr += 2;
                char *tempdomain = dealCompressPointer(buf, ptr);
                char* tempdomain1 = (unsigned char *)dns_format_to_domain(tempdomain);
                int domainlen = strlen(tempdomain + 2) + 3;
                memcpy(rdata + 2, tempdomain, domainlen);
                arrayRR[i].rdata = malloc(domainlen * sizeof(char) + 2);
                memcpy(arrayRR[i].rdata, rdata, domainlen + 2);
                ptr += arrayRR[i].data_len - 2;
                free(rdata);

                printf("Resource Record %d:\n", i + 1);
                printf(" name:%s\n", arrayRR[i].name);
                printf(" type:%s\n", querytypetoString(arrayRR[i].type));
                printf(" class:%s\n", queryClasstoString(arrayRR[i]._class));
                printf(" ttl:%us\n", arrayRR[i].ttl);
                printf(" data_len:%u\n", arrayRR[i].data_len);
                uint16_t preference= (arrayRR[i].rdata[0] << 8) | arrayRR[i].rdata[1];
                printf(" preference:%u\n", preference);
                char* exchange = dns_format_to_domain(arrayRR[i].rdata+2);
                printf(" exchange:");
                for(int j=0;j<domainlen;j++)
                {
                    printf("%c",tempdomain1[j]);
                }
                printf("\n");
                free(tempdomain);
                free(exchange);
                free(tempdomain1);
                break;
            }
            case CNAME:
            {
                char* tempdomain = dealCompressPointer(buf, ptr);
                char* tempdomain1 = (unsigned char *)dns_format_to_domain(tempdomain);
                ptr += arrayRR[i].data_len;
                arrayRR[i].data_len = strlen(tempdomain+1) + 1;
                arrayRR[i].rdata = (char *)malloc(arrayRR[i].data_len * sizeof(char));
                memcpy(arrayRR[i].rdata, tempdomain, arrayRR[i].data_len);

                printf("Resource Record %d:\n", i + 1);
                printf(" name:%s\n", arrayRR[i].name);
                printf(" type:%s\n", querytypetoString(arrayRR[i].type));
                printf(" class:%s\n", queryClasstoString(arrayRR[i]._class));
                printf(" ttl:%us\n", arrayRR[i].ttl);
                printf(" data_len:%u\n", arrayRR[i].data_len);
                printf(" cname:");
                for(int j=0;j<arrayRR[i].data_len-1;j++)
                {
                    printf("%c",tempdomain1[j]);
                }
                printf("\n");

                free(tempdomain);
                free(tempdomain1);
                break;
            }
            default:
                perror("detect:type not support\n");
                exit(1);
                break;
            }
        }
    }
    return arrayRR;
}


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <domain> <type>\n", argv[0]);
        exit(1);
    }
    DNS_RR *rr = recv_from_server(client_to_server(argv[1], stringToQueryType(argv[2])), sizeof(DNS_Header) + strlen(argv[1]) + 2 + 2 * sizeof(uint16_t));
    return 0;
}