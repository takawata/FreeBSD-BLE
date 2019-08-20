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

extern uuid_t uuid_base;
struct applewatch_service{
	int dummy;
};
void applewatch_init(struct service *service, int s);
void applewatch_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver applewatch_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = {0xd0611e78, 0xbbb4, 0x4591, 0xa5, 0xf8, {0x48,0x79,0x10,0xae,0x43,0x66}},
	.init = applewatch_init,
	.notify = applewatch_notify
};
 
void applewatch_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	int i ;
	printf("Apple Watch Notify: LEN%zu\n", len);
	for(i=0; i < len ;i ++){
		printf("%02x ", buf[i]);
	}

}
void applewatch_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	struct applewatch_service *serv;
	int cid;
	sqlite3_stmt *stmt;
	uuid_t apple_watch_chara = {0x8667556C,0x9A37,0x4C91,0x84,0xED, {0x54,0xEE, 0x27, 0xD9, 0x00, 0x49}};
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	cid = get_cid_by_uuid(service, &apple_watch_chara);
	if(cid != -1){
		register_notify(cid, service, s);
	}else{
		printf("Watch Chara not found\n");
	}

	return ;
}
