#!/bin/sh

clang -target bpf -c rainbow_kern.c -o rainbow_kern.o -O3
