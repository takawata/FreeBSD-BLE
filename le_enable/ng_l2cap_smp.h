#ifndef NG_L2CAP_SMP_H_
#define NG_L2CAP_SMP_H_
#define NG_L2CAP_SMP_PAIRREQ 1
typedef struct {
	uint8_t code;
	uint8_t iocap;
	uint8_t oobflag;
	uint8_t authreq;
	uint8_t maxkeysize;
	uint8_t ikeydist;
	uint8_t rkeydist;  
}__attribute__((packed)) ng_l2cap_smp_pairinfo;
#define NG_L2CAP_SMP_PAIRRES 2
/*use pairinfo*/
#define NG_L2CAP_SMP_PAIRCONF 3
typedef struct {
	uint8_t code;
	uint8_t body[16];
}__attribute__((packed)) ng_l2cap_smp_keyinfo;

#define NG_L2CAP_SMP_PAIRRAND 4
/*use keyinfo */
#define NG_L2CAP_SMP_PAIRFAIL 5
typedef struct {
	uint8_t code;
	uint8_t reqres;
}__attribute__((packed)) ng_l2cap_smp_reqres;
#define NG_L2CAP_SMP_ENCINFO 6
/*Use keyinfo*/
#define NG_L2CAP_SMP_MASTERINFO 7
typedef struct {
	uint8_t code;
	uint16_t ediv;
	uint8_t rand[8];
}__attribute__((packed)) ng_l2cap_smp_masterinfo;
#define NG_L2CAP_SMP_IDINFO 8
/*Use keyinfo*/
#define NG_L2CAP_SMP_IDADDR 9
typedef struct{
	uint8_t code;
	uint8_t addrtype;
	bdaddr_t bdaddr;
}__attribute__((packed)) ng_l2cap_smp_idaddr;
#define NG_L2CAP_SMP_SIGNINFO 0xa
/*Use Keyinfo */
#define NG_L2CAP_SMP_SECREQ 0xb
/*Use reqres*/
#endif
