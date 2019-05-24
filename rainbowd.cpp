#include "rainbow/packet.hpp"
#include "rainbow/reactor.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "expected.hpp"

#include <iostream>
#include <csignal>

static tl::expected<void, rainbow::Error>
process_message(const rainbow::Packet& packet)
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
  return {};
}

static tl::expected<void, rainbow::Error>
process_ipv4_udp_packet(const rainbow::Packet& packet)
{
  auto* udph = reinterpret_cast<const ::udphdr*>(packet.data);
  if (packet.len < sizeof(*udph)) {
    return tl::unexpected{"Packet is too short. Expected at least " + std::to_string(sizeof(*udph)) + ", but was: " + std::to_string(packet.len)};
  }
  std::cout << "UDP/IPv4 packet: " << ::htons(udph->len) << " bytes" << std::endl;
  return process_message(packet.trim_front(sizeof(*udph)));
}

static tl::expected<void, rainbow::Error>
process_ipv4_packet(const rainbow::Packet& packet)
{
  auto* iph = reinterpret_cast<const ::iphdr*>(packet.data);
  switch (iph->protocol) {
    case IPPROTO_UDP:
      return process_ipv4_udp_packet(packet.trim_front(sizeof(*iph)));
    case IPPROTO_TCP:
      return tl::unexpected{std::string{"TCP/IPv4 is not supported"}};
    default:
      return tl::unexpected{"Unsupported IPv4 protocol: " + std::to_string(iph->protocol)};
  }
  return {};
}

static tl::expected<void, rainbow::Error>
process_packet(const rainbow::Packet& packet)
{
  auto* eth = reinterpret_cast<const ::ethhdr*>(packet.data);
  auto offset = sizeof(*eth);
  if (offset >= packet.len) {
    return tl::unexpected{"Packet is too short. Expected at least " + std::to_string(offset) + ", but was: " + std::to_string(packet.len)};
  }
  auto proto = ::htons(eth->h_proto);
  switch (proto) {
    case ETH_P_IP:
      return process_ipv4_packet(packet.trim_front(sizeof(*eth)));
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
  try {
    rainbow::Reactor reactor;
    reactor.on_packet(process_packet);
    reactor.setup();
    while (running) {
        reactor.run_once();
    }
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << std::endl;
  }
}
