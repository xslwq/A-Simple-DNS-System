# A-Simple-DNS-System

## 实验要求

### 实验目标

深入理解DNS（Domain Name System）协议的有关知识，结合历次实验课的编程实践，完成一个基于Linux命令行终端的DNS系统原型（包括客户端和服务器），实现英文域名解析。

### 实验要求一：基本功能

1. 实现英文域名的解析
2. 至少支持4个顶级域，至少实现三级域名的解析。程序需要实现的实体有：client、至少6个DNS server（含localDNS server）。4个顶级域名：.cn、.org、.com、.us二-三级域名：自定义（例如：edu.cn，bupt.edu.cn等等
3. 支持的Resource  Record类型：A、MX、CNAME；对于MX类型的查询，要求在Additional Section中携带对应IP地址
4. 支持的解析方法：迭代解析
5. 传输层协议:client与local DNS server之间：UDP；DNS server之间：TCP
6. 应用层协议：DNS   要求通信过程中使用的所有DNS报文必须能够用wireshark正确解析
7. server的数据维护方式可采用文件
8. 书写完整的设计文档，参考Sample-Project-Report.doc
9. 程序中应包含详细的代码注释，使用良好的编程风格
10. 程序运行稳定，支持错误处理，如：命令无效、参数缺失、参数错误、查询失败等

## 实验要求二：扩展功能

1. 支持PTR类型的Resource Record
2. 支持cache
3. 打印查询的trace记录（查询路径、服务器响应时间）