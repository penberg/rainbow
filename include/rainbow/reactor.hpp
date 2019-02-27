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
  xdp_ring _tx_ring = {};
  void* _bufs = nullptr;
  int _sockfd = -1;
  OnPacketFn _fn;
  std::vector<uint64_t> tx_bufs;

public:
  ~Reactor();
  void on_packet(OnPacketFn&& fn);
  void setup();
  void send(const Packet& packet);
  void run_once();

private:
  void kick_tx();
  void teardown();
};

}
