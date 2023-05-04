#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "../include/DNS.h"

#define DNS_SERVER "8.8.8.8"
#define DNS_SERVER_PORT 53

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <domain>\n", argv[0]);
        exit(1);
    }
    int sock;
    char *domain = argv[1];
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }
    struct sockaddr_in DNShost;
    memset(&DNShost, 0, sizeof(DNShost));/*在初始化 struct sockaddr_in 结构体之后，我们需要将其余的字节位置都置为0，以免出现意外的问题。*/
    DNShost.sin_family = AF_INET;
    DNShost.sin_port = htons(DNS_SERVER_PORT);
    DNShost.sin_addr.s_addr = inet_addr(DNS_SERVER);
    char buf[1024]={0};
    DNS_Header *header = generateHeader(QUERY, 0, 0, 0, 1, 1, 0, 0, 0);
    DNS_Query *query = generateQuery(domain, A, IN);
    memcpy(buf, header, sizeof(DNS_Header));
    memcpy(buf + sizeof(DNS_Header), query, sizeof(DNS_Query));
    int sent = sendto(sock, buf, sizeof(DNS_Header) + sizeof(DNS_Query), 0, (struct sockaddr *)&DNShost, sizeof(DNShost));
    if (sent < 0)
    {
        perror("sendto");
        exit(1);
    }
    return 0;
}