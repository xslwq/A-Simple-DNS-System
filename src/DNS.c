#include"../include/DNS.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>

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