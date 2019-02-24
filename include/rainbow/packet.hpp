#pragma once

#include <cstddef> /* for size_t */

namespace rainbow {

struct Packet
{
  const char* data;
  size_t len;

  Packet(const char* data, size_t len);

  Packet trim_front(size_t size) const;
};

inline Packet::Packet(const char* data, size_t len)
  : data{data}
  , len{len}
{
}

inline Packet
Packet::trim_front(size_t nr) const
{
  auto offset = 0;
  if (len >= nr) {
    offset = nr;
  }
  return Packet{data + offset, len - offset};
}

}
