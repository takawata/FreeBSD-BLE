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
struct pasori_service{
	int dummy;
};
void pasori_init(struct service *service, int s);
void pasori_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver pasori_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = { 0x233e8100, 0x3a1b, 0x1c59, 0x9b, 0xee, {0x18,0x03,0x73,0xdd,0x03,0xa1}},
	.init = pasori_init,
	.notify = pasori_notify
};
 
void pasori_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	int i ;
	printf("Notify: LEN%zu\n", len);
	for(i=0; i < len ;i ++){
		printf("%02x ", buf[i]);
	}

}
void pasori_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	struct pasori_service *serv;
	int cid;
	sqlite3_stmt *stmt;
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	stmt = get_stmt("SELECT chara_id from ble_chara where service_id = $1;");
	sqlite3_bind_int(stmt, 1, service->service_id);
	sqlite3_step(stmt);
	cid = sqlite3_column_int(stmt,0);
	printf("%d\n", cid);
	register_notify(cid, service, cid);
	sqlite3_step(stmt);
	cid = sqlite3_column_int(stmt,0);
	register_notify(cid, service, cid);
	
	sqlite3_finalize(stmt);
	printf("PASORI:%d\n",  service->service_id);
	
	return ;
}
