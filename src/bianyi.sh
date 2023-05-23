#!/bin/bash
gcc -c DNS.c -o DNS.o
ar rcs libDNS.a DNS.o
mv libDNS.a ../lib
rm DNS.o
gcc -o DNSclient DNSclient.c -L../lib -lDNS