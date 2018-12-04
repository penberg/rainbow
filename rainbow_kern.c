#include <linux/bpf.h>

int xdp_program(struct xdp_md *ctx)
{
	return XDP_DROP;
}
