#ifndef DNSio_H
#define DNSio_H

#include <time.h>
#include "cJSON.h"
#include "DNS.h"

typedef struct
{
    
    unsigned char *name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    time_t savetime;
    unsigned short data_len;
    unsigned char *rdata;
}DNS_RR_SAVE;

void saveRRArray(cJSON *array);
void addRR(DNS_RR* RR, cJSON *array);
cJSON *readRRArray();
cJSON *getResultArraybyName(cJSON* array ,const char* name, int type);
DNS_RR* praseResult(cJSON *result);

#endif