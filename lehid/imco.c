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
#include "gatt.h"
#include <sqlite3.h>
#include <getopt.h>
#include "sql.h"
#include "service.h"
#include "att.h"
#include "uuidbt.h"

extern uuid_t uuid_base;
struct imco_service{
	int dummy;
};
void imco_init(struct service *service, int s);
void imco_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver imco_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = UUID16(0x55ff),
	.init = imco_init,
	.notify = imco_notify
};
 
void imco_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	int i ;
	printf("Notify: LEN%zu\n", len);
	for(i=0; i < len ;i ++){
		printf("%02x ", buf[i]);
	}

}
void imco_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	struct imco_service *serv;
	int cid;
	sqlite3_stmt *stmt;

	serv = malloc(sizeof(*serv));
	service->sc = serv;
	cid = get_cid_by_uuid16(service, 0x33f2);
	if(cid != -1){
		register_notify(cid, service, s);
	}	
	cid = get_cid_by_uuid16(service, 0x33f1);
	printf("WRITE CID %d\n", cid);
	return ;
}
