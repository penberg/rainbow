<img src="rainbow.png">

## What is Rainbow?

Rainbow is a Memcached-compatible high-performance in-memory key-value store (KVS) for commodity multicore hardware running Linux. State-of-art KVS servers leverage specialized hardware capabilities such as RDMA and SmartNICs or kernel-bypass techniques such as DPDK. However, specialized solutions are often hard to program and, more importantly, more difficult and expensive to deploy.

Rainbow follows a partitioned design, which shards keyspace between CPU cores that own a slice of the DRAM. The system is designed to leverage commodity multiqueue NICs and Linux's XDP packet processing interface. The server splits request processing into two parts: (1) in-kernel request pre-processing using XDP to that determines the CPU core that owns request key and (2) userspace request processing. The benefit of Rainbow's design is that CPU cores work independently of each other.

## Getting Started

### Building from Sources

First, install dependencies needed to build the system:

```console
./install-deps.sh
```

Then, specify the `LINUX_PATH` environment variable, which the build system uses to pick up location of `libbpf`:

```console
export LINUX_PATH=<path to Linux kernel sources>
```

Finally, to build the system, run:

```console
make
```

## Acknowledgements

Thanks to Björn Topel for all his help on programming with XDP!
