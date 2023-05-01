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
#include "uuidbt.h"
#include "notify.h"
#include "att.h"


extern uuid_t uuid_base;
struct batt_service{
	int battlevel;
};
void batt_init(struct service *service, int s);
void batt_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver batt_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = UUID16(0x180f),
	.init = batt_init,
	.notify = batt_notify
};
 
void batt_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	printf("Battery Level changed %d%%\n", buf[2]);
}
void batt_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	static sqlite3_stmt *stmt;
	struct batt_service *serv;
	int cid;
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	
	printf("BATT:%d\n",  service->service_id);
	cid = get_cid_by_uuid16(service, 0x2a19);
	
	len = le_char_read(s, cid, buf, sizeof(buf), 1);
	printf("%d\n", len);
	printf("Battery level %d%%\n", buf[0]);
	register_notify(cid, service, s);

	return ;
}
