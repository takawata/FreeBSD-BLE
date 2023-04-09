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
#include "notify.h"

extern uuid_t uuid_base;
struct rcs_service{
	int rcslevel;
};
void rcs_init(struct service *service, int s);
void rcs_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver rcs_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = UUID16(0x1814),
	.init = rcs_init,
	.notify = rcs_notify
};
 
void rcs_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	int flag ;
	int speed;
	double speed2;
	int cadence;
	int stride;
	int distance;
	flag= buf[2];
	speed = buf[3]|buf[4]<<8;
	cadence = buf[5];
	stride = buf[6]|buf[7]<<8;
	speed2 = speed/256.;
	distance = buf[8]|buf[9]<<8|buf[10]<<16|buf[11]<<24;
	printf("%s %d %fm/s %d/min ", (flag&4)?"Runing":"Walking",speed,speed2,cadence);
	if(flag&1)
		printf("%dcm ", stride);
	if(flag&2)
		printf("%dm", distance);
	printf("\n");
	

}
void rcs_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	static sqlite3_stmt *stmt;
	struct rcs_service *serv;
	int cid;
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	
	printf("RCS:%d\n",  service->service_id);
	cid = get_cid_by_uuid16(service, 0x2a53);
	if(cid !=-1){
		register_notify(cid, service, s);
	}
	cid = get_cid_by_uuid16(service, 0x2a54);
	if(cid != -1){
	  le_char_read(s, cid, buf, sizeof(buf), 0);
	  printf("Features %02x", buf[0]);
	}

	cid = get_cid_by_uuid16(service, 0x2a5d);
	if(cid != -1){
	  le_char_read(s, cid, buf, sizeof(buf), 0);
	  printf("SensorLocation %d", buf[0]);
	}

	return ;
}
