#!/bin/sh

LIBBPF_PATH=/home/penberg/linux/tools/lib/bpf

clang -I$LIBBPF_PATH -target bpf -c rainbow_pass_kern.c -o rainbow_pass_kern.o -O3
clang -I$LIBBPF_PATH -target bpf -c rainbow_kern.c -o rainbow_kern.o -O3
g++ -Wall -O3 -std=gnu++17 -Iinclude -I. -I$LIBBPF_PATH rainbowd.cpp reactor.cpp -o rainbowd -L$LIBBPF_PATH -l:libbpf.a -lelf
