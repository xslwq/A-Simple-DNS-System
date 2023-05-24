#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"../include/DNS.h"

int main(){
    char a []= "3www5baidu3com";
    a[0] = 3;
    a[4] = 5;
    a[9] = 3;
    char* b = dns_format_to_domain(a);
    printf("%s\n",b);
}