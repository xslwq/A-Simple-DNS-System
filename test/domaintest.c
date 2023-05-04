#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char* dns_format_to_domain(unsigned char *dns_format)
{
    char *domain = (char *)malloc(strlen((const char*)dns_format));
    int k = 0;
    while (*dns_format != 0)
    {
        int len = *dns_format++; 
        for (int i = 0; i < len; i++)
        {
            domain[k++] = *dns_format++;
        }
        if (*dns_format != 0)
        {
            domain[k++] = '.'; 
        }
    }
    domain[k] = '\0';
    return domain;
}

int main()
{
    unsigned char dns_format[] = {3, 'w', 'w', 'w', 5, 'b', 'a', 'i', 'd', 'u', 3, 'c', 'o', 'm', 0};
    char *domain = dns_format_to_domain(dns_format);
    printf("%s\n", domain);
    free(domain);
    return 0;
}
