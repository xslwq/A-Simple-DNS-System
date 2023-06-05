#include "../include/DNSio.h"
#include "../include/DNS.h"
#include "../include/cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void addRR(DNS_RR *RR, cJSON *array)
{
    time_t now = time(NULL);
    cJSON *rr = cJSON_CreateObject();
    cJSON_AddStringToObject(rr, "name", (const char *)RR->name);
    cJSON_AddNumberToObject(rr, "type", RR->type);
    cJSON_AddNumberToObject(rr, "_class", RR->_class);
    cJSON_AddNumberToObject(rr, "ttl", RR->ttl);
    cJSON_AddNumberToObject(rr, "savetime", now);
    cJSON_AddNumberToObject(rr, "data_len", RR->data_len);
    cJSON_AddStringToObject(rr, "rdata", RR->rdata);
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
        printf("Failed to open file,creating cache file...\n");
        fp = fopen("../data/RR.json", "w+");
        fclose(fp);
        cJSON *root = cJSON_CreateArray();
        return root;
    }


    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json_buffer = (char *)malloc(sizeof(char) * (file_size + 1));
    if (json_buffer == NULL)
    {
        printf("Failed to allocate memory for reading file\n");
        exit(1);
    }

    size_t read_size = fread(json_buffer, 1, file_size, fp);
    if (read_size != file_size)
    {
        printf("Failed to read file\n");
        exit(1);
    }
    json_buffer[file_size] = '\0';
    cJSON *root = cJSON_Parse(json_buffer);
    if (root == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            printf("Error before: %s\n", error_ptr);
            printf("Failed to parse json file,delete it and restart\n");
        }
        exit(1);
    }
    fclose(fp);
    free(json_buffer);
    return root;
}

cJSON *getRRbyDomain(char *domain, cJSON *array)
{
    cJSON *rr = NULL;
    cJSON_ArrayForEach(rr, array)
    {
        if (strcmp(cJSON_GetObjectItem(rr, "name")->valuestring, domain) == 0)
        {
            return rr;
        }
    }
    return NULL;
}

// generateResultArray(cJSON* ____文件缓存数组 ,const char* ____查询域名)
// 从文件缓存中查找对应的name以获得RR，记得使用CJSON_GetArraySize判断缓存内是否有对应的记录
cJSON *getResultArraybyName(cJSON *array, const char *name, int type)
{
    cJSON *result = cJSON_CreateArray();
    if (cJSON_IsArray(array))
    {
        cJSON *item = NULL;
        unsigned int index = 0u;
        cJSON_ArrayForEach(item, array)
        {
            if (cJSON_IsObject(item))
            {
                if ((strcmp(cJSON_GetObjectItem(item, "name")->valuestring, name) == 0) && (cJSON_GetObjectItem(item, "type")->valueint == type))
                {
                    if ((cJSON_GetObjectItem(item, "savetime")->valuedouble) + (cJSON_GetObjectItem(item, "ttl")->valuedouble) < (time(NULL)))
                    {
                        cJSON_DeleteItemFromArray(array, index);
                        continue;
                    }
                    cJSON_AddItemToArray(result, item);
                    index++;
                }
            }
        }
    }
    return result;
}

// praseResult(cJSON* ____查询结果数组)！！！注意！！！这个函数会释放掉传入的cJSON对象
DNS_RR *praseResult(cJSON *result)
{
    DNS_RR *resultRRarrays = malloc(cJSON_GetArraySize(result) * sizeof(DNS_RR));
    cJSON *item = NULL;
    unsigned int index = 0u;
    cJSON_ArrayForEach(item, result)
    {
        if (cJSON_IsObject(item))
        {
            resultRRarrays[index].name = cJSON_GetObjectItem(item, "name")->valuestring;
            resultRRarrays[index].type = cJSON_GetObjectItem(item, "type")->valueint;
            resultRRarrays[index]._class = cJSON_GetObjectItem(item, "_class")->valueint;
            resultRRarrays[index].ttl = cJSON_GetObjectItem(item, "ttl")->valueint;
            resultRRarrays[index].data_len = cJSON_GetObjectItem(item, "data_len")->valueint;
            resultRRarrays[index].rdata = strdup(cJSON_GetObjectItem(item, "rdata")->valuestring);
            index++;
        }
    }
    free(result);
    return resultRRarrays;
}