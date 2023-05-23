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

#define RECV_BUF_SIZE 1024
#define DEFAULT_SERVER "8.8.8.8"
#define DNS_SERVER_PORT 53

DNS_RR *getRR(char *buf, int sendDataOffset, uint16_t awnserNum);
DNS_RR *recv_from_server(int sock, int sendDataOffset);
int client_to_server(const char *domain, DNS_QUERY_TYPE querytype);
char *dealCompressPointer(char *buf, int ptr);

int client_to_server(const char *domain, DNS_QUERY_TYPE querytype)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in DNShost;
    memset(&DNShost, 0, sizeof(DNShost)); /*在初始化 struct sockaddr_in 结构体之后，我们需要将其余的字节位置都置为0，以免出现意外的问题。*/
    DNShost.sin_family = AF_INET;
    DNShost.sin_port = htons(DNS_SERVER_PORT);
    DNShost.sin_addr.s_addr = inet_addr(DEFAULT_SERVER);

    DNS_Header *header = generateHeader(Q, QUERY, 0, 0, 0, 1, 0, 0, 0); // 报头参数：_QUERY类型,_操作码,_是否递归查询,_响应码,_是否截断,_问题数,_回答数,_授权数,_附加数
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

    return sock;
}

DNS_RR *recv_from_server(int sock, int sendDataOffset)
{
    char *recvbuf = (char *)malloc(RECV_BUF_SIZE);
    struct sockaddr_in DNShost;
    memset(&DNShost, 0, sizeof(DNShost));
    socklen_t len = sizeof(DNShost);
    int recvlen = recvfrom(sock, recvbuf, RECV_BUF_SIZE, 0, (struct sockaddr *)&DNShost, &len);
    if (recvlen < 0)
    {
        perror("recvfrom");
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
    printf("sendDataOffset:%d\n", sendDataOffset);
    printf("comp:%u\n", comp);
    for (int i = 0; i < awnserNum; i++)
    {
        if ((comp & 0xc000) >> 14 != 0x03) // RR非压缩指针
        {
            printf("RR非压缩指针\n");
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
            printf("RR压缩指针\n");
            size = 0;
            uint16_t compptr = ((buf[ptr] << 8) | buf[ptr + 1]) & 0x3fff;
            printf("compptr:%u\n", compptr);
            for (int j = compptr;; j++)
            {
                if (buf[j] == 0)
                {
                    size = j - compptr + 1;
                    break;
                }
            }
            printf("size:%d\n", size);
            arrayRR[i].name = (char *)malloc(size * sizeof(char));
            memcpy(arrayRR[i].name, buf + compptr, size);
            arrayRR[i].name = (unsigned char *)dns_format_to_domain(arrayRR[i].name);
            printf("arrayRR[i].name:%s\n", arrayRR[i].name);
            ptr += 2;
            memcpy(&(arrayRR[i].type), buf + ptr, 2);
            memcpy(&(arrayRR[i]._class), buf + ptr + 2, 2);
            memcpy(&(arrayRR[i].ttl), buf + ptr + 4, 4);
            memcpy(&(arrayRR[i].data_len), buf + ptr + 8, 2);
            arrayRR[i].type = ntohs(arrayRR[i].type);
            arrayRR[i]._class = ntohs(arrayRR[i]._class);
            arrayRR[i].ttl = ntohl(arrayRR[i].ttl);
            arrayRR[i].data_len = ntohs(arrayRR[i].data_len);
            printf("arrayRR[i].type:%u\n", arrayRR[i].type);
            printf("arrayRR[i]._class:%u\n", arrayRR[i]._class);
            printf("arrayRR[i].ttl:%u\n", arrayRR[i].ttl);
            printf("arrayRR[i].data_len:%u\n", arrayRR[i].data_len);
            ptr += 10;
            switch (arrayRR[i].type)//目前只支持A、MX、CNAME
            {
            case A:
            {
                printf("A\n");
                arrayRR[i].rdata = (char *)malloc(arrayRR[i].data_len * sizeof(char));
                memcpy(arrayRR[i].rdata, buf + ptr, arrayRR[i].data_len);
                ptr += arrayRR[i].data_len;
                break;
            }
            case MX:
            {
                printf("MX\n");
                char *rdata = (char *)malloc(256 * sizeof(char));
                memcpy(rdata, buf + ptr, 2);
                ptr += 2;
                char *tempdomain = dealCompressPointer(buf,ptr);
                tempdomain = (unsigned char *)dns_format_to_domain(tempdomain);
                memcpy(rdata+2,tempdomain,strlen(tempdomain)+1);
                arrayRR[i].rdata =malloc(strlen(tempdomain)*sizeof(char)+2);
                memcpy(arrayRR[i].rdata,rdata,strlen(tempdomain)+3);
                printf("arrayRR[i].rdata:%s\n",arrayRR[i].rdata+2);
                ptr += arrayRR[i].data_len;
                break;
            }
            case CNAME:
            {
                printf("CNAME\n");
                arrayRR[i].rdata = dealCompressPointer(buf,ptr);
                arrayRR[i].rdata = (unsigned char *)dns_format_to_domain(arrayRR[i].rdata);
                arrayRR[i].data_len = strlen(arrayRR[i].rdata);
                ptr += arrayRR[i].data_len;
                break;
            }
            default:
                perror("type not support\n");
                exit(1);
                break;
            }
        }
    }
    return arrayRR;
}

char *dealCompressPointer(char *buf, int ptr)
{
    int domainlen = 0;
    char *completedomain = (char *)malloc(256 * sizeof(char));
    int i=ptr;
    int j=0;
    int compptr = 0;
    printf("1");
    while (1)
    {
        printf("1");
        if (buf[i] == 0)
        {
            completedomain[domainlen] = buf[i];
            break;
        }
        else
        if ((buf[i] & 0xc0) == 0xc0)
        {
            compptr = ((buf[i] << 8) | buf[i + 1]) & 0x3fff;
            for(j=compptr;;j++)
            {
                if(buf[j]==0)
                {
                    domainlen += 1;
                    memcpy(completedomain + domainlen, buf + j, 1);
                    break;
                }
                else
                {
                    domainlen += 1;
                    memcpy(completedomain + domainlen, buf + j, 1);
                }
            }
            break;
        }
        else
        {
            domainlen += 1;
            memcpy(completedomain + domainlen, buf + i, 1);
            i += 1;
        }
    }
    char *rdata = (char *)malloc(domainlen * sizeof(char));
    memcpy(rdata, completedomain, domainlen);
    free(completedomain);
    return rdata;
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