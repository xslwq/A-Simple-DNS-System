#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/DNS.h"

#define DEFAULT_SERVER "8.8.8.8"
#define DNS_SERVER_PORT 53

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <domain> <type>\n", argv[0]);
        exit(1);
    }
    DNS_RR*rr = recv_from_server(client_to_server(argv[1],stringToQueryType(argv[2])), sizeof(DNS_Header) + strlen(argv[1]) + 1 + sizeof(stringToQueryType(argv[2])) + sizeof(IN));
    return 0;
}

