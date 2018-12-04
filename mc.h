#ifndef RAINBOW_MC_H
#define RAINBOW_MC_H

struct mchdr {
	__u8 magic;
	__u8 opcode;
	__u16 key_len;
	__u8 extras_len;
	__u8 data_type;
	__u16 vbucket_id;
	__u32 body_len;
	__u32 opaque;
	__u64 cas;
};

#endif
