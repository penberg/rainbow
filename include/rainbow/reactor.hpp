#pragma once

#include "expected.hpp"

#include <functional>

namespace rainbow {

struct Packet;

using Error = std::string;

using OnPacketFn = std::function<tl::expected<void, Error>(const Packet& packet)>;

class Reactor
{
  OnPacketFn _fn;

public:
  void on_packet(OnPacketFn&& fn);
  void run();
};

}
