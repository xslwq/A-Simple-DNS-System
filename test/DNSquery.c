#include <stdio.h>
#include <stdlib.h>

#include "../include/DNS.h"

#define DEFAULT_SERVER "8.8.8.8"
#define DNS_SERVER_PORT 53

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <domain>\n", argv[0]);
        exit(1);
    }
    int sock=send_query_to_DNS_server(argv[1],A);
    return 0;
}