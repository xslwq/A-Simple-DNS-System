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
    rr->ttl = 1;
    rr->data_len = 4;
    char *ip = "avvq";
    rr->rdata = malloc(4);
    memcpy(rr->rdata, ip, 4);

    cJSON *array = cJSON_CreateArray();
    addRR(rr, array);

    DNS_RR *rr1 = (DNS_RR *)malloc(sizeof(DNS_RR));
    char *domain1 = "www.zhihu.com";
    rr1->name = malloc(strlen(domain1) + 1);
    memcpy(rr1->name, domain1, strlen(domain1));
    rr1->name[strlen(domain1)] = '\0';
    rr1->type = A;
    rr1->_class = A;
    rr1->ttl = 1;
    rr1->data_len = 4;
    char *ip1 = "pqsd";
    rr1->rdata = malloc(4);
    memcpy(rr1->rdata, ip1, 4);

    addRR(rr1, array);
    saveRRArray(array);
    char *domain2 = "www.baidu.com";
    sleep(3);
    cJSON* awnserArray =  getResultArraybyName(array,domain2);
    cJSON *item1;
    printf("%d\n", cJSON_GetArraySize(awnserArray));
    if (cJSON_IsArray(awnserArray))
    {
        cJSON_ArrayForEach(item1, awnserArray)
        {
            if (cJSON_IsObject(item1))
            {
                printf("%s\n", cJSON_GetObjectItem(item1, "name")->valuestring);
                printf("%d\n", cJSON_GetObjectItem(item1, "type")->valueint);
                printf("%d\n", cJSON_GetObjectItem(item1, "_class")->valueint);
                printf("%d\n", cJSON_GetObjectItem(item1, "ttl")->valueint);
                printf("%d\n", cJSON_GetObjectItem(item1, "savetime")->valueint);
                printf("%ld\n", time(NULL));
                printf("%d\n", cJSON_GetObjectItem(item1, "data_len")->valueint);
                printf("%s\n", cJSON_GetObjectItem(item1, "rdata")->valuestring);
                printf("%c %c %c %c\n", *cJSON_GetObjectItem(item1, "rdata")->valuestring, *(cJSON_GetObjectItem(item1, "rdata")->valuestring + 1), *(cJSON_GetObjectItem(item1, "rdata")->valuestring + 2), *(cJSON_GetObjectItem(item1, "rdata")->valuestring + 3));
            }
        }
    }
    return 0;
}