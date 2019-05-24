ifeq ($(LINUX_PATH),)
  $(error LINUX_PATH is not set)
endif

LIBBPF_PATH = $(LINUX_PATH)/tools/lib/bpf

EBPF_PROGRAMS += rainbow_pass_kern.o
EBPF_PROGRAMS += rainbow_kern.o

PROGRAMS += rainbowd

all: $(EBPF_PROGRAMS) $(PROGRAMS)

rainbow_pass_kern.o:
	clang -I$(LIBBPF_PATH) -target bpf -c rainbow_pass_kern.c -o rainbow_pass_kern.o -O3

rainbow_kern.o:
	clang -I$(LIBBPF_PATH) -target bpf -c rainbow_kern.c -o rainbow_kern.o -O3

rainbowd:
	make -C $(LIBBPF_PATH) all
	g++ -Wall -O3 -std=gnu++17 -Iinclude -I. -I$(LIBBPF_PATH) rainbowd.cpp reactor.cpp -o rainbowd -L$(LIBBPF_PATH) -l:libbpf.a -lelf

clean:
	rm -f $(EBPF_PROGRAMS) $(PROGRAMS)
