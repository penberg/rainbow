#include <iostream>
#include <system_error>

#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_xdp.h>

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

static void
server()
{
  auto sockfd = ::socket(AF_XDP, SOCK_RAW, 0);
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
  auto* rx_map = ::mmap(nullptr,
                        off.rx.desc + nr_descs * sizeof(struct xdp_desc),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE,
                        sockfd,
                        XDP_PGOFF_RX_RING);
  if (rx_map == MAP_FAILED) {
    throw std::system_error(errno, std::system_category(), "mmap(XDP_PGOFF_RX_RING)");
  }
  auto* tx_map = ::mmap(nullptr,
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
  saddr.sxdp_ifindex = if_nametoindex("lo");
  saddr.sxdp_queue_id = 0;
  if (::bind(sockfd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
    throw std::system_error(errno, std::system_category(), "bind");
  }
  ::close(sockfd);
}

int
main()
{
  try {
    server();
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << std::endl;
  }
}
