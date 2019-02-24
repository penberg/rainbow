#include "rainbow/reactor.hpp"

#include "rainbow/packet.h"

#include <atomic>
#include <iostream>
#include <system_error>

#include "expected.hpp"

#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_xdp.h>

extern "C" {
#include <bpf.h>
#include <libbpf.h>
}

namespace rainbow {

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

struct xdp_umem_ring
{
  uint64_t* desc;
  uint32_t* producer;
  uint32_t* consumer;
  uint32_t mask;
};

struct xdp_ring
{
  struct xdp_desc* desc;
  uint32_t* producer;
  uint32_t* consumer;
  uint32_t mask;
};

void
Reactor::on_packet(OnPacketFn&& fn)
{
  _fn = std::move(fn);
}

void
Reactor::run()
{
  int err;
  auto ifindex = if_nametoindex("lo");
  ::bpf_prog_load_attr prog_load_attr = {
    .prog_type = BPF_PROG_TYPE_XDP,
  };
  prog_load_attr.file = "rainbow_pass_kern.o";
  ::bpf_object* obj;
  int progfd;
  err = bpf_prog_load_xattr(&prog_load_attr, &obj, &progfd);
  if (err < 0) {
    throw std::system_error(-err, std::system_category(), "bpf_prog_load_xattr");
  }
  err = bpf_set_link_xdp_fd(ifindex, progfd, 0);
  if (err < 0) {
    throw std::system_error(-err, std::system_category(), "bpf_set_link_xdp_fd");
  }
  ::bpf_map *map = bpf_object__find_map_by_name(obj, "xsks_map");
  int xsks_map = bpf_map__fd(map);
  if (xsks_map < 0) {
    throw std::system_error(-xsks_map, std::system_category(), "bpf_map__fd");
  }
  int sockfd = ::socket(AF_XDP, SOCK_RAW, 0);
  if (sockfd < 0) {
    throw std::system_error(errno, std::system_category(), "socket(AF_XDP)");
  }
  void* bufs = nullptr;
  int frame_size = 2048;
  int nr_frames = 131072;
  if (::posix_memalign(&bufs, ::getpagesize(), nr_frames * frame_size) < 0) {
    throw std::system_error(errno, std::system_category(), "posix_memalign");
  }
  ::xdp_umem_reg umem_region;
  umem_region.addr = reinterpret_cast<uint64_t>(bufs);
  umem_region.len = nr_frames * frame_size;
  umem_region.chunk_size = frame_size;
  umem_region.headroom = 0;
  if (::setsockopt(sockfd, SOL_XDP, XDP_UMEM_REG, &umem_region, sizeof(umem_region)) < 0) {
    throw std::system_error(errno, std::system_category(), "setsockopt(SOL_XDP, XDP_UMEM_REG)");
  }
  int fill_queue_size = 1024;
  if (::setsockopt(sockfd, SOL_XDP, XDP_UMEM_FILL_RING, &fill_queue_size, sizeof(int)) < 0) {
    throw std::system_error(errno, std::system_category(), "setsockopt(SOL_XDP, XDP_UMEM_FILL_RING)");
  }
  int completion_queue_size = 1024;
  if (::setsockopt(sockfd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &completion_queue_size, sizeof(int)) < 0) {
    throw std::system_error(errno, std::system_category(), "setsockopt(SOL_XDP, XDP_UMEM_COMPLETION_RING)");
  }
  int nr_descs = 1024;
  if (::setsockopt(sockfd, SOL_XDP, XDP_RX_RING, &nr_descs, sizeof(int)) < 0) {
    throw std::system_error(errno, std::system_category(), "setsockopt(SOL_XDP, XDP_RX_RING)");
  }
  if (::setsockopt(sockfd, SOL_XDP, XDP_TX_RING, &nr_descs, sizeof(int)) < 0) {
    throw std::system_error(errno, std::system_category(), "setsockopt(SOL_XDP, XDP_TX_RING)");
  }
  ::xdp_mmap_offsets off;
  socklen_t optlen = sizeof(off);
  if (::getsockopt(sockfd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
    throw std::system_error(errno, std::system_category(), "getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)");
  }
  void* fill_ring_mmap = ::mmap(nullptr,
                                off.fr.desc + fill_queue_size * sizeof(uint64_t),
                                PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_POPULATE,
                                sockfd,
                                XDP_UMEM_PGOFF_FILL_RING);
  if (fill_ring_mmap == MAP_FAILED) {
    throw std::system_error(errno, std::system_category(), "mmap(XDP_UMEM_PGOFF_FILL_RING)");
  }
  xdp_umem_ring fill_ring;
  fill_ring.desc = reinterpret_cast<uint64_t*>(reinterpret_cast<uint64_t>(fill_ring_mmap) + off.fr.desc);
  fill_ring.producer = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(fill_ring_mmap) + off.fr.producer);
  fill_ring.consumer = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(fill_ring_mmap) + off.fr.consumer);
  fill_ring.mask = fill_queue_size - 1;

  void* completion_ring_mmap = ::mmap(nullptr,
                                      off.cr.desc + completion_queue_size * sizeof(uint64_t),
                                      PROT_READ | PROT_WRITE,
                                      MAP_SHARED | MAP_POPULATE,
                                      sockfd,
                                      XDP_UMEM_PGOFF_COMPLETION_RING);
  if (completion_ring_mmap == MAP_FAILED) {
    throw std::system_error(errno, std::system_category(), "mmap(XDP_UMEM_PGOFF_COMPLETION_RING)");
  }
  xdp_umem_ring completion_ring;
  completion_ring.desc = reinterpret_cast<uint64_t*>(reinterpret_cast<uint64_t>(completion_ring_mmap) + off.cr.desc);
  completion_ring.producer = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(completion_ring_mmap) + off.cr.producer);
  completion_ring.consumer = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(completion_ring_mmap) + off.cr.consumer);
  completion_ring.mask = completion_queue_size - 1;

  void* rx_map = ::mmap(nullptr,
                        off.rx.desc + nr_descs * sizeof(struct xdp_desc),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE,
                        sockfd,
                        XDP_PGOFF_RX_RING);
  if (rx_map == MAP_FAILED) {
    throw std::system_error(errno, std::system_category(), "mmap(XDP_PGOFF_RX_RING)");
  }
  for (uint64_t i = 0; i < uint64_t(nr_descs * frame_size); i += frame_size) {
    fill_ring.desc[(*fill_ring.producer)++ & fill_ring.mask] = i;
  }
  void* tx_map = ::mmap(nullptr,
                        off.rx.desc + nr_descs * sizeof(struct xdp_desc),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE,
                        sockfd,
                        XDP_PGOFF_TX_RING);
  if (tx_map == MAP_FAILED) {
    throw std::system_error(errno, std::system_category(), "mmap(XDP_PGOFF_TX_RING)");
  }
  ::sockaddr_xdp saddr;
  saddr.sxdp_family = AF_XDP;
  saddr.sxdp_ifindex = ifindex;
  saddr.sxdp_queue_id = 0;
  if (::bind(sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
    throw std::system_error(errno, std::system_category(), "bind");
  }
  int key = 0;
  err = bpf_map_update_elem(xsks_map, &key, reinterpret_cast<void*>(&sockfd), 0);
  if (err) {
    throw std::system_error(errno, std::system_category(), "bpf_map_update_elem()");
  }
  xdp_ring rx_ring = {};
  rx_ring.producer = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(rx_map) + off.rx.producer);
  rx_ring.consumer = reinterpret_cast<uint32_t*>(reinterpret_cast<uint64_t>(rx_map) + off.rx.consumer);
  rx_ring.desc = reinterpret_cast<struct xdp_desc*>(reinterpret_cast<uint64_t>(rx_map) + off.rx.desc);
  rx_ring.mask = nr_descs - 1;
  for (;;) {
    if (*rx_ring.producer != *rx_ring.consumer) {
      // Use an acquire fence ("read barrier") to ensure we test if the ring is
      // empty or not before dequeuing a descriptor from it.
      std::atomic_thread_fence(std::memory_order_acquire);
      struct xdp_desc desc = rx_ring.desc[(*rx_ring.consumer)++ & rx_ring.mask];
      Packet packet{reinterpret_cast<const char*>(reinterpret_cast<uint64_t>(bufs) + desc.addr), desc.len};
      auto ret = _fn(packet);
      if (!ret) {
        std::cout << "warning: Packet processing error: " << ret.error() << std::endl;
      }
      fill_ring.desc[(*fill_ring.producer)++ & fill_ring.mask] = desc.addr;
    }
    std::atomic_thread_fence(std::memory_order::memory_order_seq_cst);
  }
  ::close(sockfd);
}

}

