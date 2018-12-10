#!/bin/sh

clang -target bpf -c rainbow_kern.c -o rainbow_kern.o -O3
g++ -Wall -O3 -std=gnu++17 rainbowd.cpp -o rainbowd
