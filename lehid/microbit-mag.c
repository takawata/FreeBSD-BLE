#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/bitstring.h>
#include <sys/select.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <openssl/aes.h>
#include <netgraph/ng_message.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include "hccontrol.h"
#include "gatt.h"
#include <sqlite3.h>
#include <getopt.h>
#include "sql.h"
#include "service.h"
#include "att.h"
#include "uuidbt.h"
static void microbit_mag_notify(void *sc, int charid, unsigned char *buf, size_t len);
static void microbit_mag_init(struct service *service, int s);
struct microbit_mag_service
{
	int interval;
	int itv_cid;
	int mag_cid;
	int bear_cid;
};

struct service_driver microbit_mag_driver __attribute__((used)) __attribute((section("driver"))) =
{
	.uuid = { 0xe95df2d8,0x251d,0x470a,0xa0, 0x62,{0xfa,0x19,0x22,0xdf,0xa9,0xa8}},
	.init = &microbit_mag_init,
	.notify = &microbit_mag_notify,
};

static void microbit_mag_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	struct microbit_mag_service *serv = sc; 
	int16_t x,y,z,b;
	int i;
	if(charid == serv->mag_cid){
		x = buf[2]|(buf[3]<<8);
		y = buf[4]|(buf[5]<<8);
		z = buf[6]|(buf[7]<<8);
		for(i = 0 ; i < len;i++){
			printf("%02x ", buf[i]);
		}
		printf("\n");
		printf("LEN %dMag X:%d Y%d Z%d\n",len, x,y,z);
	}else if(charid == serv->bear_cid){
		b = buf[2]|(buf[3]<<8);
		printf("Bear %d\n", b);
	}
}

static void microbit_mag_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	struct microbit_mag_service *serv;
	int cid;
	sqlite3_stmt *stmt;
	uuid_t microbit_mag_chara = {0xe95dfb11,0x251d,0x470a,0xa0,0x62,{0xfa,0x19,0x22,0xdf,0xa9,0xa8}};
	uuid_t microbit_interval_chara = {0xe95d386c,0x251d,0x470a,0xa0,0x62,{0xfa,0x19,0x22,0xdf,0xa9,0xa8}};
	uuid_t microbit_bear_chara = {0xe95d9715,0x251d,0x470a,0xa0,0x62,{0xfa,0x19,0x22,0xdf,0xa9,0xa8}};
	
	serv = malloc(sizeof(*serv));
	service->sc = serv;

	
	cid = get_cid_by_uuid(service, &microbit_mag_chara);
	if(cid != -1){
		serv->mag_cid = cid;
		register_notify(cid, service, s);
	}else{
		printf("Service MAG Chara not found\n");
	}
	cid = get_cid_by_uuid(service, &microbit_bear_chara);
	if(cid != -1){
		serv->bear_cid = cid;
		register_notify(cid, service, s);
	}else{
		printf("Service MAG Chara not found\n");
	}
	
	serv->itv_cid = get_cid_by_uuid(service, &microbit_interval_chara);
	if(cid != -1){
		int i;
		len = le_char_read(s, serv->itv_cid, buf, sizeof(buf), 1);
		serv->interval = (buf[1]<<8)|(buf[0]);
		buf[0]=2;
		buf[1]=0;
		le_char_write(s, serv->itv_cid, buf, 2, 0);
		printf("Interval: %d\n", serv->interval);
	}else{
		printf("Interval CIDNot Found\n");
	}
	return ;
}
