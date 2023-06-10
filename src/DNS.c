#include "../include/DNS.h"
#include "../include/cJSON.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

#define DEFAULT_SERVER "114.114.114.114"
#define DNS_SERVER_PORT 53
#define RECV_BUF_SIZE 1024

// 生成Flags字段
uint16_t setFlag(int QR, int Opcode, int RA, int RCODE, int TC)
{
    uint16_t flags = 0;
    flags |= QR << 15;
    flags |= Opcode << 11;
    flags |= TC << 9;
    flags |= RA << 8;
    flags |= 0 << 6; // 设置 Z 标志位为 0
    flags |= 0 << 5; // 设置 AD 标志位为 0，表示未使用 DNSSEC 验证
    flags |= 0 << 4; // 设置 CD 标志位为 0，表示未要求 DNSSEC 验证
    flags |= RCODE;
    return flags;
}
// 生成随机ID
uint16_t generateID()
{
    srand(time(NULL));
    return rand() % 0xFFFF;
}

// 根据参数生成DNS报头，用法：generateHeader(_QUERY类型,_操作码,_是否递归查询,_响应码,_是否截断,_问题数,_回答数,_授权数,_附加数)
DNS_Header *generateHeader(DNS_TYPE type, int Opcode, int RA, int RCODE, int TC, int queryNum, int answerNum, int authorNum, int addNum, uint16_t ID)
{
    DNS_Header *header = (DNS_Header *)malloc(sizeof(DNS_Header));
    memset(header, 0, sizeof(DNS_Header));
    header->id = htons(ID);
    header->flags = htons(setFlag(type, Opcode, RA, RCODE, TC));
    header->queryNum = htons(queryNum);
    header->answerNum = htons(answerNum);
    header->authorNum = htons(authorNum);
    header->addNum = htons(addNum);
    return header;
}
// 生成DNS查询报文，用法：generateQuery(_域名,_查询类型,_查询类)
DNS_Query *generateQuery(const char *domain, DNS_QUERY_TYPE qtype, DNS_QUERY_CLASS qclass)
{
    DNS_Query *query = (DNS_Query *)malloc(sizeof(DNS_Query));
    memset(query, 0, sizeof(DNS_Query));
    query->name = domain_to_dns_format(domain);
    query->qtype = htons(qtype);
    query->qclass = htons(qclass);
    return query;
}
// 一般域名转换为DNS格式
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
// DNS格式转换为一般域名
char *dns_format_to_domain(unsigned char *dns_format)
{
    int len = strlen(dns_format);
    char *domain = (char *)malloc(len * sizeof(char));
    int sectionLen = 0;
    int i = 0;
    int ptr = 0;
    sectionLen = dns_format[i];
    while (1)
    {
        for (i = ptr; i < ptr + sectionLen; i++)
        {
            domain[i] = dns_format[i + 1];
        }
        if (dns_format[ptr + sectionLen] == 0)
            break;
        domain[ptr + sectionLen] = '.';
        ptr = ptr + sectionLen + 1;
        sectionLen = dns_format[ptr];
    }
    domain[len - 1] = '\0';
    return domain;
}
// 字符串转换为查询类型
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
    else if (strcmp(str, "PTR") == 0)
    {
        return PTR;
    }
    else if (strcmp(str, "MX") == 0)
    {
        return MX;
    }
    else
    {
        fprintf(stderr, "Invalid query type!\n");
        exit(1);
        return 0;
    }
}
 // 查询类型转换为字符串
char *querytypetoString(DNS_QUERY_TYPE type)
{
    switch (type)
    {
    case A:
        return "A";
    case NS:
        return "NS";
    case CNAME:
        return "CNAME";
    case PTR:
        return "PTR";
    case MX:
        return "MX";
    default:
        return "Invalid query type!";
    }
}
// 查询错误类型
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

//字符串转网络类型
DNS_QUERY_CLASS stringtoQueryClass(char *str)
{
    if (strcmp(str, "IN") == 0)
    {
        return IN;
    }
    else if (strcmp(str, "CS") == 0)
    {
        return CS;
    }
    else if (strcmp(str, "CH") == 0)
    {
        return CH;
    }
    else if (strcmp(str, "HS") == 0)
    {
        return HS;
    }
    else
    {
        fprintf(stderr, "Invalid query class!\n");
        exit(1);
        return 0;
    }
}

// 网络类型转字符串
char *queryClasstoString(DNS_QUERY_CLASS class)
{
    switch (class)
    {
    case IN:
        return "IN";
    case CS:
        return "CS";
    case CH:
        return "CH";
    case HS:
        return "HS";
    default:
        return "Invalid query class!";
    }
}

// 根据buffer和指针处理压缩指针
char *dealCompressPointer(char *buf, int ptr)
{
    int domainlen = 0;
    char *completedomain = (char *)malloc(256 * sizeof(char));
    int i = ptr;
    int j = 0;
    int compptr = 0;
    while (1)
    {
        if (buf[i] == 0)
        {
            completedomain[domainlen] = buf[i];
            break;
        }
        else if ((buf[i] & 0xc0) == 0xc0)
        {
            compptr = ((buf[i] << 8) | buf[i + 1]) & 0x3fff;
            for (j = compptr;; j++)
            {
                if (buf[j] == 0)
                {
                    memcpy(completedomain + domainlen, buf + j, 1);
                    domainlen += 1;
                    break;
                }
                else
                {
                    memcpy(completedomain + domainlen, buf + j, 1);
                    domainlen += 1;
                }
            }
            break;
        }
        else
        {
            memcpy(completedomain + domainlen, buf + i, 1);
            domainlen += 1;
            i += 1;
        }
    }
    char *rdata = (char *)malloc(domainlen * sizeof(char));
    memcpy(rdata, completedomain, domainlen);
    free(completedomain);
    return rdata;
}

// 字符串IP转换为网络类型
char* IPStringtocharIP(const char* IPString){
    char* ip = (char*)malloc(4*sizeof(char));
    struct in_addr addr;
    inet_pton(AF_INET, IPString, &addr);
    memcpy(ip, &addr.s_addr, 4);
    return ip;
} 
// 网络类型IP转换为字符串
char* CharIPtoIPString(const char* CharIP){
    char* ip = (char*)malloc(16*sizeof(char));
    struct in_addr addr;
    memcpy(&addr.s_addr, CharIP, 4);
    inet_ntop(AF_INET, &addr,ip , INET_ADDRSTRLEN);
    return ip;
}

// 翻转报头
void parseHeader(DNS_Header *header)
{
    header->id = ntohs(header->id);
    header->flags = ntohs(header->flags);
    header->queryNum = ntohs(header->queryNum);
    header->answerNum = ntohs(header->answerNum);
    header->authorNum = ntohs(header->authorNum);
    header->addNum = ntohs(header->addNum);
}