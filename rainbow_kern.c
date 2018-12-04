#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

#include "murmur3.h"
#include "mc.h"

#define MAX_CPUS 64

#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_redirect_map)(void *map, int key, int flags) = (void *) BPF_FUNC_redirect_map;

struct bpf_map_info SEC("maps") cpu_map = {
	.type		= BPF_MAP_TYPE_CPUMAP,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(__u32),
	.max_entries	= MAX_CPUS,
};

static __u16 htons(__u16 n)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap16(n);
#else
	return n;
#endif
}

static int process_packet(void *start, void *end)
{
	struct ethhdr *eth = start;
	__u64 offset = sizeof(*eth);
	if (start + offset > end) {
		return XDP_PASS;
	}
	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	struct iphdr *iph = start + offset;
	offset += sizeof(*iph);
	if (start + offset > end) {
		return XDP_PASS;
	}
	if (iph->protocol != IPPROTO_UDP) {
		return XDP_PASS;
	}
	struct udphdr *udph = start + offset;
	offset += sizeof(*udph);
	if (start + offset > end) {
		return XDP_PASS;
	}
	struct mchdr *mch = start + offset;
	offset += sizeof(*mch);
	offset += mch->extras_len;
	void *key_start = start + offset;
	offset += mch->key_len;
	if (start + offset > end) {
		return XDP_PASS;
	}
	__u64 seed = 1;
	__u32 hash;
	MurmurHash3_x86_32(key_start, mch->key_len, seed, (void*) &hash);
	__u32 cpu_dest = hash % MAX_CPUS;
	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

int xdp_program(struct xdp_md *ctx)
{
	void *start = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	return process_packet(start, end);
}
