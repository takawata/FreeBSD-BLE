#include <uuid.h>
#include <sys/endian.h>
#include "uuidbt.h"

void uuid_enc_bt(void *buf, const uuid_t *uuid)
{
	uint8_t *d = buf;
	int i;
	
	le32enc(d+12, uuid->time_low);
	le16enc(d+10, uuid->time_mid);
	le16enc(d+8, uuid->time_hi_and_version);
	d[7] = uuid->clock_seq_hi_and_reserved;
	d[6] = uuid->clock_seq_low;
	for(i = 0; i < _UUID_NODE_LEN; i++)
		d[5-i] = uuid->node[i];
}

void uuid_dec_bt( const void *buf, uuid_t *uuid)
{
	uint8_t *p = buf;
	int i;

	uuid->time_low = le32dec(p+12);
	uuid->time_mid = le16dec(p+10);
	uuid->time_hi_and_version = le16dec(p+8);
	uuid->clock_seq_hi_and_reserved = p[7];
	uuid->clock_seq_low = p[6];
	for(i = 0; i < _UUID_NODE_LEN; i++){
		uuid->node[i] = p[5 - i];
	}
}	
