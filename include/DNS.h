#ifndef DNS_H
#define DNS_H

#include <stdint.h>

typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t queryNum;
    uint16_t answerNum;
    uint16_t authorNum;
    uint16_t addNum;
} DNS_Header;

typedef struct
{
    unsigned char *name;
    uint16_t qtype;
    uint16_t qclass;
} DNS_Query;

typedef struct
{
    unsigned char *name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned char *rdata;
}DNS_RR;


typedef enum
{
    Q = 0,
    R = 1
} DNS_TYPE;

typedef enum
{
    NOERROR = 0,
    FORMATERROR = 1,
    SERVERERROR = 2,
    NAMEERROR = 3,
    NOTIMPLEMENTED = 4,
    REFUSED = 5
} DNS_RCODE;

typedef enum
{
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2
} DNS_OPCODE;

typedef enum
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    AXFR = 252,
    ANY = 255
} DNS_QUERY_TYPE;

typedef enum
{
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
} DNS_QUERY_CLASS;

uint16_t setFlag(int QR, int Opcode, int RA, int RCODE, int TC);
uint16_t generateID();

DNS_Header *generateHeader(DNS_TYPE type, int Opcode, int RA, int RCODE, int TC, int queryNum, int answerNum, int authorNum, int addNum);

char *dns_format_to_domain(unsigned char *dns_format);

DNS_Query *generateQuery(const char *domain, DNS_QUERY_TYPE qtype, DNS_QUERY_CLASS qclass);

unsigned char *domain_to_dns_format(const char *domain);
unsigned char *bind_header_query(DNS_Header *header, DNS_Query *query);

void isNOERROR(uint16_t flags);

DNS_QUERY_TYPE stringToQueryType(const char* str);

#endif
