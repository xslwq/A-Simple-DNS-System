#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../include/DNSio.h"
#include "../include/DNS.h"


int main()
{
    cJSON *RRarray = readRRArray();
    char *domain2 = "www.baidu.com";
    
    cJSON *item1=NULL;
    cJSON_ArrayForEach(item1, RRarray)
    {
        printf("%s\n", cJSON_GetObjectItem(item1, "name")->valuestring);
        printf("%d\n", cJSON_GetObjectItem(item1, "type")->valueint);
    }
    cJSON* awnserArray =  getResultArraybyName(RRarray,domain2, CNAME);
    printf("%d\n", cJSON_GetArraySize(awnserArray));
    return 0;
}