#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<time.h>
#include<sys/types.h>
#include<netinet/in.h>
#
#include"../include/DNS.h"

#define MAX_BUFFER_SIZE 512
int main(){
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;

    server_socket = socket(AF_INET, SOCK_DGRAM, 0);

    // 绑定地址和端口
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(53);
    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    while (1) {
        char buf[MAX_BUFFER_SIZE];
        // 接收客户端发送的数据
        socklen_t client_addr_len = sizeof(client_addr);
        recvfrom(server_socket, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        printf("Received message: %s\n", buf);

        // 发送数据到客户端
        sendto(server_socket, "Hello, client!", strlen("Hello, client!"), 0, (struct sockaddr *)&client_addr, client_addr_len);
    }

    close(server_socket);

    return 0;
}