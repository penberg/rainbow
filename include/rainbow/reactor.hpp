#pragma once

#include "expected.hpp"

#include <functional>

#include <linux/if_xdp.h>

namespace rainbow {

struct Packet;

using Error = std::string;

using OnPacketFn = std::function<tl::expected<void, Error>(const Packet& packet)>;

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

class Reactor
{
  unsigned int _ifindex = 0;
  xdp_umem_ring _fill_ring = {};
  xdp_ring _rx_ring = {};
  void* _bufs = nullptr;
  int _sockfd = -1;
  OnPacketFn _fn;

public:
  ~Reactor();
  void on_packet(OnPacketFn&& fn);
  void setup();
  void run_once();

private:
  void teardown();
};

}
