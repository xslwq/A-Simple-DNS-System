#include"../include/DNS.h"
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

//根据参数生成DNS报头，用法：generateHeader(_QUERY类型,_操作码,_是否递归查询,_响应码,_是否截断,_问题数,_回答数,_授权数,_附加数)
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

char* dns_format_to_domain(unsigned char *dns_format)
{
    char *domain = (char *)malloc(strlen((const char*)dns_format));
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
//将报头和查询部分绑定在一起
unsigned char* bind_header_query(DNS_Header *header, DNS_Query *query)
{
    unsigned char *buf = (unsigned char *)malloc(sizeof(DNS_Header) + strlen((const char *)query->name) + 1 + sizeof(query->qtype) + sizeof(query->qclass));
    memcpy(buf, header, sizeof(DNS_Header));
    memcpy(buf + sizeof(DNS_Header), query->name, strlen(query->name) + 1);
    memcpy(buf + sizeof(DNS_Header) + strlen(query->name) + 1, &query->qtype, sizeof(query->qtype));
    memcpy(buf + sizeof(DNS_Header) + strlen(query->name) + 1 + sizeof(query->qtype), &query->qclass, sizeof(query->qclass));
    return buf;
}

int send_query_to_DNS_server(const char *domain, DNS_QUERY_TYPE querytype)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in DNShost;
    memset(&DNShost, 0, sizeof(DNShost));/*在初始化 struct sockaddr_in 结构体之后，我们需要将其余的字节位置都置为0，以免出现意外的问题。*/
    DNShost.sin_family = AF_INET;
    DNShost.sin_port = htons(DNS_SERVER_PORT);
    DNShost.sin_addr.s_addr = inet_addr(DEFAULT_SERVER);

    unsigned char *buf=bind_header_query(generateHeader(query, QUERY, 0, 0, 0, 1, 0, 0, 0), generateQuery(domain, querytype, IN));
    
    int sent = sendto(sock, buf, sizeof(buf), 0, (struct sockaddr *)&DNShost, sizeof(DNShost));
    if (sent < 0)
    {
        perror("sendto");
        exit(1);
    }
    free(buf);
    return sock;
}