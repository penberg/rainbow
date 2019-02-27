#include "rainbow/packet.hpp"
#include "rainbow/reactor.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <netinet/ip.h>

#include "expected.hpp"

#include <iostream>
#include <csignal>

class Buffer {
  char *_data;
  size_t _offset;
  size_t _size;
public:
  Buffer(char *data, size_t size);
  void append_ethhdr(int proto);
  void append_iphdr(uint32_t saddr, uint32_t daddr, uint16_t len);
  void append_udphdr(uint16_t source, uint16_t dest, uint16_t len);
  void append_data(const rainbow::Packet& packet);
  rainbow::Packet to_packet() const;
private:
  template<typename T>
  T* allocate();
};

Buffer::Buffer(char *data, size_t size)
  : _data{data}
  , _offset{0}
  , _size{size}
{
}

void
Buffer::append_ethhdr(int proto)
{
  auto *eth = allocate<::ethhdr>();
  std::fill_n(eth->h_dest, ETH_ALEN, 0);
  std::fill_n(eth->h_source, ETH_ALEN, 0);
  eth->h_proto = htons(proto);
}

void
Buffer::append_iphdr(uint32_t saddr, uint32_t daddr, uint16_t len)
{
  auto iph = allocate<::iphdr>();
  iph->version = IPVERSION;
  iph->ihl = 5;
  iph->tot_len = ::htons(sizeof(::iphdr) + len);
  iph->id = ::htons(0xdead); // FIXME: what is this?
  iph->frag_off = ::htons(IP_DF); // DF -- don't fragment.
  iph->ttl = 0x40; // FIXME: where did this magic number come from?
  iph->protocol = IPPROTO_UDP;
  // FIXME: Verify that XDP has IP checksum offloading.
  iph->check = ::htons(0xcafe);
  iph->saddr = ::htonl(saddr);
  iph->daddr = ::htonl(daddr);
}

void
Buffer::append_udphdr(uint16_t source, uint16_t dest, uint16_t len)
{
  auto udph = allocate<::udphdr>();
  udph->source = ::htons(source);
  udph->dest = ::htons(dest);
  udph->len = ::htons(sizeof(::udphdr) + len);
  // FIXME: Verify that XDP has UDP checksum offloading.
  udph->check = htons(0x0000);
}

void
Buffer::append_data(const rainbow::Packet& packet)
{
  // FIXME: bounds check
  std::copy_n(packet.data, packet.len, _data + _offset);
  _offset += packet.len;
}

rainbow::Packet
Buffer::to_packet() const
{
  return rainbow::Packet{_data, _offset};
}

template<typename T>
T* Buffer::allocate()
{
  size_t start = _offset;
  // FIXME: bounds check
  _offset += sizeof(T);
  return reinterpret_cast<T*>(_data + start);
}

static void
print_packet(const rainbow::Packet& packet)
{
  for (size_t i = 0; i < packet.len; i++) {
    unsigned char ch = packet.data[i];
    printf("%02x ", ch);
  }
  printf("  |");
  for (size_t i = 0; i < packet.len; i++) {
    char ch = packet.data[i];
    if (std::isprint(ch)) {
      printf("%c", ch);
    } else {
      printf(".");
    }
  }
  printf("|\n");
}

inline const size_t mtu = 1500;
inline const size_t max_frame_size = sizeof(::ethhdr) + mtu;

static tl::expected<void, rainbow::Error>
process_message(rainbow::Reactor& reactor, uint32_t saddr, uint32_t daddr, uint16_t source, uint16_t dest, const rainbow::Packet& packet)
{
  char data[max_frame_size];
  std::fill_n(data, max_frame_size, 0); // FIXME: debugging
  Buffer response{data, max_frame_size};
  response.append_ethhdr(ETH_P_IP);
  response.append_iphdr(saddr, daddr, sizeof(::udphdr) + packet.len);
  response.append_udphdr(source, dest, packet.len);
  response.append_data(packet);
  std::cout << "Outgoing packet:" << std::endl;
  print_packet(response.to_packet());
  reactor.send(response.to_packet());
  return {};
}

static tl::expected<void, rainbow::Error>
process_ipv4_udp_packet(rainbow::Reactor& reactor, uint32_t saddr, uint32_t daddr, const rainbow::Packet& packet)
{
  auto* udph = reinterpret_cast<const ::udphdr*>(packet.data);
  if (packet.len < sizeof(*udph)) {
    return tl::unexpected{"Packet is too short. Expected at least " + std::to_string(sizeof(*udph)) + ", but was: " + std::to_string(packet.len)};
  }
  auto source = ::ntohs(udph->source);
  auto dest = ::ntohs(udph->dest);
  auto len = ::ntohs(udph->len);
  std::cout << "UDP/IPv4 packet source=" << source << ", dest=" << dest << ", len=" << len << std::endl;
  return process_message(reactor, daddr, saddr, dest, source, packet.trim_front(sizeof(*udph)));
}

static tl::expected<void, rainbow::Error>
process_ipv4_packet(rainbow::Reactor& reactor, const rainbow::Packet& packet)
{
  auto* iph = reinterpret_cast<const ::iphdr*>(packet.data);
  switch (iph->protocol) {
    case IPPROTO_UDP: {
      auto saddr = ::ntohl(iph->saddr);
      auto daddr = ::ntohl(iph->daddr);
      std::cout << "IPv4 packet saddr=" << saddr << ", daddr=" << daddr << std::endl;
      return process_ipv4_udp_packet(reactor, saddr, daddr, packet.trim_front(sizeof(*iph)));
    }
    case IPPROTO_TCP:
      return tl::unexpected{std::string{"TCP/IPv4 is not supported"}};
    default:
      return tl::unexpected{"Unsupported IPv4 protocol: " + std::to_string(iph->protocol)};
  }
  return {};
}

static tl::expected<void, rainbow::Error>
process_packet(rainbow::Reactor& reactor, const rainbow::Packet& packet)
{
  std::cout << "Incoming packet:" << std::endl;
  print_packet(packet);
  auto* eth = reinterpret_cast<const ::ethhdr*>(packet.data);
  auto offset = sizeof(*eth);
  if (offset >= packet.len) {
    return tl::unexpected{"Packet is too short. Expected at least " + std::to_string(offset) + ", but was: " + std::to_string(packet.len)};
  }
  auto proto = ::htons(eth->h_proto);
  switch (proto) {
    case ETH_P_IP:
      return process_ipv4_packet(reactor, packet.trim_front(sizeof(*eth)));
    case ETH_P_IPV6:
      return tl::unexpected{std::string{"IPv6 is not supported"}};
    default:
      return tl::unexpected{"Unsupported EtherType: " + std::to_string(proto)};
  }
}

static bool running = true;

static void
signal_handler(int, siginfo_t*, void*)
{
  running = false;
}

static void
setup_signal(int signum)
{
  struct ::sigaction sa{};
  sa.sa_sigaction = signal_handler;
  sa.sa_flags = SA_SIGINFO;
  auto err = sigaction(signum, &sa, nullptr);
  if (err) {
    throw std::system_error(errno, std::system_category());
  }
}

int
main()
{
  setup_signal(SIGINT);
  setup_signal(SIGTERM);
  using namespace std::placeholders;
  try {
    rainbow::Reactor reactor;
    reactor.setup();
    reactor.on_packet(std::bind(process_packet, std::ref(reactor), _1));
    while (running) {
        reactor.run_once();
    }
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << std::endl;
  }
}
