#!/bin/sh

clang -I/home/penberg/linux/tools/lib/bpf -target bpf -c rainbow_pass_kern.c -o rainbow_pass_kern.o -O3
clang -I/home/penberg/linux/tools/lib/bpf -target bpf -c rainbow_kern.c -o rainbow_kern.o -O3
g++ -Wall -O3 -std=gnu++17 -Iinclude -I/home/penberg/linux/tools/lib/bpf rainbowd.cpp -o rainbowd -L/home/penberg/linux/tools/lib/bpf -l:libbpf.a -lelf
