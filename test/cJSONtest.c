#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../include/DNSio.h"
#include "../include/DNS.h"

int main()
{
    DNS_RR *rr = (DNS_RR *)malloc(sizeof(DNS_RR));
    char *domain = "www.baidu.com";
    rr->name = malloc(strlen(domain) + 1);
    memcpy(rr->name, domain, strlen(domain));
    rr->name[strlen(domain)] = '\0';
    rr->type = A;
    rr->_class = A;
    rr->ttl = 10;
    rr->data_len = 4;
    char *ip = "avvq";
    rr->rdata = malloc(4);
    memcpy(rr->rdata, ip, 4);

    cJSON *array = cJSON_CreateArray();
    addRR(rr, array);

    DNS_RR *rr1 = (DNS_RR *)malloc(sizeof(DNS_RR));
    char *domain1 = "www.baidu.com";
    rr1->name = malloc(strlen(domain1) + 1);
    memcpy(rr1->name, domain1, strlen(domain1));
    rr1->name[strlen(domain1)] = '\0';
    rr1->type = A;
    rr1->_class = CNAME;
    rr1->ttl = 10;
    rr1->data_len = 17;
    char *ip1 = "www.a.shifen.com";
    rr1->rdata = malloc(18);
    memcpy(rr1->rdata, ip1, 17);
    rr1->rdata[17] = '\0';

    addRR(rr1, array);
    saveRRArray(array);
    char *domain2 = "www.baidu.com";
    //sleep(3);
    printf("rrname:%s\n", rr->name);
    printf("rrname:%s\n", rr1->name);
    cJSON* awnserArray =  getResultArraybyName(array,domain2);
    cJSON *item1;
    printf("%d\n", cJSON_GetArraySize(awnserArray));
    DNS_RR *result=praseResult(awnserArray);

    printf("%s\n",result[0].rdata);
    return 0;
}