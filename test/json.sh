#!/bin/bash
cd ../src
gcc -c DNS.c -o DNS.o
ar rcs libDNS.a DNS.o
mv libDNS.a ../lib
rm DNS.o
gcc -c DNSio.c -o DNSio.o
ar rcs libDNSio.a DNSio.o
mv libDNSio.a ../lib
rm DNSio.o
gcc -c cJSON.c -o cJSON.o
ar rcs libcJSON.a cJSON.o
mv libcJSON.a ../lib
rm cJSON.o
cd ../test
gcc -o cJSONtest cJSONtest.c -L../lib -lcJSON -lDNSio -lDNS