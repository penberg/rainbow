#!/bin/sh

clang -target bpf -c rainbow_kern.c -o rainbow_kern.o -O2
clang -target bpf -c murmur3.c -o murmur3.o -O2
