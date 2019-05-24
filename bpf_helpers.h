#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

static int (*bpf_redirect_map)(struct bpf_map_def *map, __u32 key, __u64 flags) =
	(void *) BPF_FUNC_redirect_map;

#endif
