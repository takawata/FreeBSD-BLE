
#define OMRONID(x){				\
	.time_low = 0x0c4c0000+(x),		\
	.time_mid = 0x7700,			\
	.time_hi_and_version = 0x46f4,		\
	.clock_seq_hi_and_reserved = 0xaa,	\
	.clock_seq_low = 0x96, \
	.node = { 0xD5, 0xE9, 0x74, 0xE3, 0x2A, 0x54}	\
}

inline void omron_id(uint16_t x, uuid_t *u)
{
    const uuid_t b = OMRONID(0);
    *u = b;
    u->time_low |= x;
}
