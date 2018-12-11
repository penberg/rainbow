#include <linux/bpf.h>
#include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#define MAX_SOCKS 4

struct bpf_map_def SEC("maps") xsks_map = {
        .type = BPF_MAP_TYPE_XSKMAP,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = MAX_SOCKS,
};

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	return bpf_redirect_map(&xsks_map, 0, 0);
}
