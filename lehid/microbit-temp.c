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
static void microbit_temp_notify(void *sc, int charid, unsigned char *buf, size_t len);
static void microbit_temp_init(struct service *service, int s);
struct microbit_temp_service
{
	int interval;
	int itv_cid;
	int temp;
};

struct service_driver microbit_temp_driver __attribute__((used)) __attribute((section("driver"))) =
{
	.uuid = { 0xe95d6100,0x251d,0x470a,0xa0, 0x62,{0xfa,0x19,0x22,0xdf,0xa9,0xa8}},
	.init = &microbit_temp_init,
	.notify = &microbit_temp_notify,
};

static void microbit_temp_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	struct microbit_temp_service *serv = sc; 
	int i;
	serv->temp = buf[2];

	printf("Temp %d\n",serv->temp);
}

static void microbit_temp_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	struct microbit_temp_service *serv;
	int cid;
	sqlite3_stmt *stmt;
	uuid_t microbit_temp_chara = {0xe95d9250,0x251d,0x470a,0xa0,0x62,{0xfa,0x19,0x22,0xdf,0xa9,0xa8}};
	uuid_t microbit_interval_chara = {0xe95d1b25,0x251d,0x470a,0xa0,0x62,{0xfa,0x19,0x22,0xdf,0xa9,0xa8}};	
	serv = malloc(sizeof(*serv));
	service->sc = serv;

	
	cid = get_cid_by_uuid(service, &microbit_temp_chara);
	if(cid != -1){
		len= le_char_read(s, cid, buf, sizeof(buf), 1);
		printf("LEN %d: %x %x\n", len, buf[0], buf[1]);
		serv->temp = buf[0];
		printf("TEMP: %d\n", serv->temp);
		register_notify(cid, service, s);
	}else{
		printf("Service TEMP Chara not found\n");
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
