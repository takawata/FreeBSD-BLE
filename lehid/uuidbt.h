#ifndef UUIDBT_H_
#define UUIDBT_H_
#include <uuid.h>

#define UUID16(x) { \
    .time_low = (x),\
    .time_mid = 0x0000,\
    .time_hi_and_version = 0x1000,\
    .clock_seq_hi_and_reserved = 0x80,\
    .clock_seq_low = 0x00,\
  .node = { 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb}\
}

static inline void btuuid16(uint16_t x, uuid_t *u)
{
  uuid_t p = UUID16(x);
  
  *u = p;
}

void uuid_enc_bt(void *buf, const uuid_t *uuid);
void uuid_dec_bt(const void *buf, uuid_t *uuid);
void btuuiddec(void * buf, int len,uuid_t *uuid);

#endif
