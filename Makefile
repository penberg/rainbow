ifeq ($(LINUX_PATH),)
  $(error LINUX_PATH is not set)
endif

LIBBPF_PATH = $(LINUX_PATH)/tools/lib/bpf

EBPF_PROGRAMS += rainbow_pass_kern.o
EBPF_PROGRAMS += rainbow_kern.o

EBPF_INCLUDES += -I$(LIBBPF_PATH)
# FIXME: Ubuntu and x86-64 specific include:
EBPF_INCLUDES += -I/usr/include/x86_64-linux-gnu/

PROGRAMS += rainbowd

CXXFLAGS = -Wall -O2 -std=gnu++17

INCLUDES = -Iinclude -I. -I$(LIBBPF_PATH)

OBJS += rainbowd.o reactor.o

all: $(EBPF_PROGRAMS) $(PROGRAMS)

rainbow_pass_kern.o:
	clang $(EBPF_INCLUDES) -target bpf -c rainbow_pass_kern.c -o rainbow_pass_kern.o -O3

rainbow_kern.o:
	clang $(EBPF_INCLUDES) -target bpf -c rainbow_kern.c -o rainbow_kern.o -O3

%.o: %.cpp
	g++ $(CXXFLAGS) $(INCLUDES) -c $<

rainbowd: $(OBJS)
	make -C $(LIBBPF_PATH) all
	g++ $(CXXFLAGS) $(INCLUDES) $(OBJS) -o rainbowd -L$(LIBBPF_PATH) -l:libbpf.a -lelf

clean:
	rm -f $(EBPF_PROGRAMS) $(PROGRAMS)
	make -C $(LIBBPF_PATH) clean
