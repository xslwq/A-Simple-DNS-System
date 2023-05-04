#ifndef DNS_H
#define DNS_H

#include<stdint.h>

typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t queryNum;
    uint16_t answerNum;
    uint16_t authorNum;
    uint16_t addNum;
}DNS_Header;

typedef struct
{
    unsigned char *name;
    uint16_t qtype;
    uint16_t qclass;
}DNS_Query;

typedef enum 
{
    query = 0,
    response = 1
}DNS_TYPE;  

typedef enum{
    NOERROR = 0,
    FORMATERROR = 1,
    SERVERERROR = 2,
    NAMEERROR = 3,
    NOTIMPLEMENTED = 4,
    REFUSED = 5
}DNS_RCODE;

typedef enum{
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2
}DNS_OPCODE;

#endif

