#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
    /*
    struct sockaddr_in {
    sa_family_t sin_family;      // 地址族，一般为 AF_INET（IPv4）
    in_port_t sin_port;          // 端口号
    struct in_addr sin_addr;     // IP地址
    char sin_zero[8];           // 保留字段，填充0
    }*/
#define DNS_SERVER "8.8.8.8"
#define DNS_SERVER_PORT 53
/*
id：16位无符号整数，用于标识DNS消息。在发送DNS查询请求时，该字段由客户端生成；在DNS服务器返回响应消息时，该字段保持与请求消息中的ID相同。
flags：16位无符号整数，用于表示DNS消息的各种标志位。
queryNum：16位无符号整数，表示DNS查询请求消息中查询问题的数量。
answerNum：16位无符号整数，表示DNS响应消息中回答的资源记录数量。
authorNum：16位无符号整数，表示DNS响应消息中授权的资源记录数量。
addNum：16位无符号整数，表示DNS响应消息中附加的资源记录数量。

QR (1 bit)：指示该报文是查询报文 (0) 还是响应报文 (1)。
Opcode (4 bits)：指示查询类型，如标准查询 (0)、反向查询 (1)、服务器状态请求 (2) 等。
AA (1 bit)：授权回答 (1) 或非授权回答 (0)。
TC (1 bit)：指示报文是否被截断，如果报文过大，会被分成多个数据包传输。
RD (1 bit)：请求递归解析 (1) 或非递归解析 (0)。
RA (1 bit)：指示 DNS 服务器是否支持递归解析请求。
Z (3 bits)：保留字段，通常设置为 0。
RCODE (4 bits)：响应码，指示响应报文的类型，如无错误 (0)、名称错误 (3)、服务器错误 (2) 等。
常见的RCODE值包括：
0: 没有错误
1: 格式错误
2: 服务器错误
3: 名字错误
4: 查询类型不支持
5: 拒绝
6-15: 保留字段
*/
typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t queryNum;
    uint16_t answerNum;
    uint16_t authorNum;
    uint16_t addNum;
}DNS_Header;

/*qname:A记录：查询主机的IPv4地址，qtype值为0x0001。
CNAME记录：查询别名记录，qtype值为0x0005。
MX记录：查询邮件交换记录，qtype值为0x000f。
NS记录：查询域名服务器记录，qtype值为0x0002。
SOA记录：查询起始授权机构记录，qtype值为0x0006。
AAAA记录：查询主机的IPv6地址，qtype值为0x001c。
PTR记录：反向查询记录，qtype值为0x000c。
TXT记录：文本记录，qtype值为0x0010。

qclass:IN：表示Internet类别，即IPv4或IPv6地址。这是最常用的类别，也是默认值。
CS：表示CSNET类别，已经很少使用。
CH：表示CHAOS类别，通常用于DNS服务器内部通信。
HS：表示Hesiod类别，用于分布式数据库系统的域名解析。
因为IN类别是最常用的，所以在实际应用中，qclass字段的值通常都被设置为0x0001，表示IN类别。
如果要查询其他类别的资源记录，需要将qclass字段设置为相应的取值，
例如0x0002表示CS类别，0x0003表示CH类别，0x0004表示HS类别。

*/
typedef struct
{
    unsigned char *name;
    uint16_t qtype;
    uint16_t qclass;
}DNS_Query;

typedef enum 
{
    query = 0,
    response = 1
}DNS_TYPE;  

typedef enum{
    NOERROR = 0,
    FORMATERROR = 1,
    SERVERERROR = 2,
    NAMEERROR = 3,
    NOTIMPLEMENTED = 4,
    REFUSED = 5
}DNS_RCODE;

typedef enum{
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2
}DNS_OPCODE;

uint16_t setFlag(int QR, int Opcode, int RA, int RCODE, int TC)
{
    uint16_t flags = 0;
    flags |= QR << 15;
    flags |= Opcode << 11;
    flags |= TC << 9;
    flags |= RA << 7;
    flags |= 0 << 6; // 设置 Z 标志位为 0
    flags |= 0 << 5; // 设置 AD 标志位为 0，表示未使用 DNSSEC 验证
    flags |= 0 << 4; // 设置 CD 标志位为 0，表示未要求 DNSSEC 验证
    flags |= RCODE;
    return flags;
}

uint16_t generateID()
{
    srand(time(NULL));
    return rand() % 0xFFFF;
}

DNS_Header *generateHeader(DNS_TYPE type, int Opcode, int RA, int RCODE, int TC, int queryNum, int answerNum, int authorNum, int addNum)
{
    DNS_Header *header = (DNS_Header *)malloc(sizeof(DNS_Header));
    header->id = generateID();
    header->flags = setFlag(type, Opcode, RA, RCODE, TC);
    header->queryNum = queryNum;
    header->answerNum = answerNum;
    header->authorNum = authorNum;
    header->addNum = addNum;
    return header;
}

int main(int argc, char *argv[])
{
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
    DNS_Header header={0};
}