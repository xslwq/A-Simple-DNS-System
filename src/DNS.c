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

#define DEFAULT_SERVER "8.8.8.8"
#define DNS_SERVER_PORT 53
#define RECV_BUF_SIZE 1024

uint16_t setFlag(int QR, int Opcode, int RA, int RCODE, int TC)
{
    uint16_t flags = 0;
    flags |= QR << 15;
    flags |= Opcode << 11;
    flags |= TC << 9;
    flags |= RA << 7;
    flags |= 0 << 6; // 设置 Z 标志位为 0
    flags |= 0 << 5; // 设置 AD 标志位为 0，表示未使用 DNSSEC 验证
    flags |= 0 << 4; // 设置 CD 标志位为 0，表示未要求 DNSSEC 验证
    flags |= RCODE;
    return flags;
}

uint16_t generateID()
{
    srand(time(NULL));
    return rand() % 0xFFFF;
}

// 根据参数生成DNS报头，用法：generateHeader(_QUERY类型,_操作码,_是否递归查询,_响应码,_是否截断,_问题数,_回答数,_授权数,_附加数)
DNS_Header *generateHeader(DNS_TYPE type, int Opcode, int RA, int RCODE, int TC, int queryNum, int answerNum, int authorNum, int addNum)
{
    DNS_Header *header = (DNS_Header *)malloc(sizeof(DNS_Header));
    memset(header, 0, sizeof(DNS_Header));
    header->id = htons(generateID());
    header->flags = htons(setFlag(type, Opcode, RA, RCODE, TC));
    header->queryNum = htons(queryNum);
    header->answerNum = htons(answerNum);
    header->authorNum = htons(authorNum);
    header->addNum = htons(addNum);
    return header;
}

DNS_Query *generateQuery(const char *domain, DNS_QUERY_TYPE qtype, DNS_QUERY_CLASS qclass)
{
    DNS_Query *query = (DNS_Query *)malloc(sizeof(DNS_Query));
    memset(query, 0, sizeof(DNS_Query));
    query->name = domain_to_dns_format(domain);
    query->qtype = htons(qtype);
    query->qclass = htons(qclass);
    return query;
}

unsigned char *domain_to_dns_format(const char *domain)
{
    int len = strlen(domain);
    unsigned char *dns_format = (unsigned char *)malloc(len + 2);
    memset(dns_format, 0, len + 2);
    int sectionLen = 0;
    int i, j;
    for (i = 0, j = 0; i < len; i++)
    {
        if (domain[i] == '.')
        {
            dns_format[j] = sectionLen;
            j = i + 1;
            sectionLen = 0;
        }
        else
        {
            dns_format[i + 1] = domain[i];
            sectionLen++;
        }
    }
    dns_format[j] = sectionLen;
    dns_format[len + 1] = '\0';
    return dns_format;
}

char *dns_format_to_domain(unsigned char *dns_format)
{
    char *domain = (char *)malloc(strlen((const char *)dns_format));
    int k = 0;
    while (*dns_format != 0)
    {
        int len = *dns_format++;
        for (int i = 0; i < len; i++)
        {
            domain[k++] = *dns_format++;
        }
        if (*dns_format != 0)
        {
            domain[k++] = '.';
        }
    }
    domain[k] = '\0';
    return domain;
}

DNS_QUERY_TYPE stringToQueryType(const char *str)
{
    if (strcmp(str, "A") == 0)
    {
        return A;
    }
    else if (strcmp(str, "NS") == 0)
    {
        return NS;
    }
    else if (strcmp(str, "CNAME") == 0)
    {
        return CNAME;
    }
    else if (strcmp(str, "SOA") == 0)
    {
        return SOA;
    }
    else if (strcmp(str, "PTR") == 0)
    {
        return PTR;
    }
    else if (strcmp(str, "MX") == 0)
    {
        return MX;
    }
    else if (strcmp(str, "TXT") == 0)
    {
        return TXT;
    }
    else if (strcmp(str, "AAAA") == 0)
    {
        return AAAA;
    }
    else if (strcmp(str, "SRV") == 0)
    {
        return SRV;
    }
    else if (strcmp(str, "AXFR") == 0)
    {
        return AXFR;
    }
    else if (strcmp(str, "ANY") == 0)
    {
        return ANY;
    }
    else
    {
        fprintf(stderr, "Invalid query type!\n");
        exit(1);
        return 0;
    }
}

void isNOERROR(uint16_t flags)
{

    switch (flags & 0x000F)
    {
    case NOERROR:
        break;
    case FORMATERROR:
        fprintf(stderr, "Recieved Data: Format error\n");
        exit(1);
        break;
    case SERVERERROR:
        fprintf(stderr, "Recieved Data: Server error\n");
        exit(1);
        break;
    case NAMEERROR:
        fprintf(stderr, "Recieved Data: Name error\n");
        exit(1);
        break;
    case NOTIMPLEMENTED:
        fprintf(stderr, "Recieved Data: Not implemented\n");
        exit(1);
        break;
    case REFUSED:
        fprintf(stderr, "Recieved Data: Refused\n");
        exit(1);
        break;
    }
}

// 将报头和查询部分绑定在一起（已弃用）
unsigned char *bind_header_query(DNS_Header *header, DNS_Query *query)
{
    unsigned char *buf = (unsigned char *)malloc(sizeof(DNS_Header) + strlen((const char *)query->name) + 1 + sizeof(query->qtype) + sizeof(query->qclass));
    memcpy(buf, header, sizeof(DNS_Header));
    memcpy(buf + sizeof(DNS_Header), query->name, strlen(query->name) + 1);
    memcpy(buf + sizeof(DNS_Header) + strlen(query->name) + 1, &query->qtype, sizeof(query->qtype));
    memcpy(buf + sizeof(DNS_Header) + strlen(query->name) + 1 + sizeof(query->qtype), &query->qclass, sizeof(query->qclass));
    printf("buf:%lu\n", sizeof(DNS_Header) + strlen((const char *)query->name) + 1 + sizeof(query->qtype) + sizeof(query->qclass));
    return buf;
}

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

    if (sent < 0)
    {
        perror("sendto");
        exit(1);
    }

    recv_from_server(sock, sendbufferlen);

    return sock;
}

void recv_from_server(int sock, int sendDataOffset)
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
    }
}

DNS_RR *getRR(char *buf, int sendDataOffset, uint16_t awnserNum)
{
    printf("1\n");
    DNS_RR *arrayRR = (DNS_RR *)malloc(awnserNum * sizeof(DNS_RR));
    memset(arrayRR, 0, awnserNum * sizeof(DNS_RR));
    int ptr = sendDataOffset;
    int size = 0;
    int i = 0;
    //  for(int i=0;i<awnserNum;i++){
    for (int j = ptr; buf[ptr] != 0; j++)
    {
        if (buf[j] = 0)
            size = j - ptr + 1;
    }
    arrayRR[i].name = (char *)malloc(size * sizeof(char));
    memcpy(arrayRR[i].name, buf + ptr, size);
    arrayRR[i].name = (unsigned char *)dns_format_to_domain(arrayRR[i].name);
    unsigned char dns_format[] = {3, 'w', 'w', 'w', 5, 'b', 'a', 'i', 'd', 'u', 3, 'c', 'o', 'm', 0};
    char *s = dns_format_to_domain(dns_format);
    printf("name:%s\n", s);
        printf("name:");
    for(int i=0;i<15;i++){
        printf("%c",arrayRR[0].name[i]);
    }
    printf("\n");
    printf("namelen:%lu\n",strlen(s));
    //  }
    return arrayRR;
}
