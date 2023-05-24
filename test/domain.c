#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"../include/DNS.h"

int main(){
    char a []= ".1.1.1";
    a[0] = 1;
    a[2] = 1;
    a[4] = 1;
    char* b = dns_format_to_domain(a);
    printf("%s\n",b);
    printf("%c\n",b[9]+48);
    free(b);
}