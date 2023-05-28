#include "../include/DNSio.h"
#include "../include/DNS.h"
#include "../include/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


void addRR(DNS_RR RR, cJSON *array)
{
    time_t now=time(NULL);
    cJSON *rr = cJSON_CreateObject();
    cJSON_AddStringToObject(rr, "name", (const char *)RR.name);
    cJSON_AddNumberToObject(rr, "type", RR.type);
    cJSON_AddNumberToObject(rr, "_class", RR._class);
    cJSON_AddNumberToObject(rr, "ttl", RR.ttl);
    cJSON_AddNumberToObject(rr, "savetime", now);
    cJSON_AddNumberToObject(rr, "data_len", RR.data_len);
    cJSON_AddStringToObject(rr, "rdata", RR.rdata);
    cJSON_AddItemToArray(array, rr);
}

void saveRRArray(cJSON *array)
{
    FILE *fp = fopen("../data/RR.json", "w+");
    char *out = cJSON_Print(array);
    fwrite(out, sizeof(char), strlen(out), fp);
    fclose(fp);
}

cJSON *readRRArray()
{
    FILE *fp = fopen("../data/RR.json", "r");
    if (fp == NULL)
    {
        printf("Failed to open file\n");
        exit(1);
    }
    char *json_str = NULL;
    size_t len = 0;
    ssize_t read = getline(&json_str, &len, fp);
    if (read == -1)
    {
        printf("Failed to read file\n");
        exit(1);
    }
    cJSON *root = cJSON_Parse(json_str);
    if (root == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("Error before: %s\n", error_ptr);
        }
        exit(1);
    }
    fclose(fp);
    free(json_str);
    return root;
}