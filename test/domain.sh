#!/bin/bash
cd ../src
gcc -c DNS.c -o DNS.o
ar rcs libDNS.a DNS.o
mv libDNS.a ../lib
rm DNS.o
cd ../test
gcc -o domain domain.c -L../lib -lDNS