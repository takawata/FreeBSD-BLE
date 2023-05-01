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
struct csc_service{
    int cpcid;
    uint32_t previous_time;
    uint32_t previous_cnt;
};
void csc_init(struct service *service, int s);
void csc_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver csc_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = UUID16(0x1816),
	.init = csc_init,
	.notify = csc_notify
};
 
void csc_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
    int i,cur;
    int wheelflag = buf[2]&1;
    int crankflag = buf[2]&2;
    uint32_t cumwheel = 0;
    uint32_t wheeltime = 0;
    uint32_t cumcrank = 0;
    uint32_t cranktime = 0;
    printf("%zu:", len);
    cur = 3;
    if(wheelflag){
	for(i = 0; i < 4; i++,cur++){
	    cumwheel |= (buf[cur]<<(i*8));
	}
	for(i = 0; i < 2; i++,cur++){
	    wheeltime |= (buf[cur]<<(i*8));
	}
	printf("%d %lf\n", cumwheel, (double)wheeltime/1024.);
    }
    if(crankflag){
	for(i = 0; i < 2; i++,cur++){
	    cumcrank |= (buf[cur]<<(i*8));
	}
	for(i = 0; i < 2; i++,cur++){
	    cranktime |= (buf[cur]<<(i*8));
	}
	
	printf("%d %lf\n", cumcrank, (double)cranktime/1024.);	
    }
}
void csc_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	static sqlite3_stmt *stmt;
	struct csc_service *serv;
	int cid;
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	
	printf("CSC:%d\n",  service->service_id);
	cid = get_cid_by_uuid16(service, 0x2a5c);
	
	len = le_char_read(s, cid, buf, sizeof(buf), 1);
	printf("Feature %d\n", buf[0]|(buf[1]<<8));

	cid = get_cid_by_uuid16(service, 0x2a5d);
	len = le_char_read(s, cid, buf, sizeof(buf), 1);
	printf("Location %d\n", buf[0]);
	cid = get_cid_by_uuid16(service, 0x2a5b);
	register_notify(cid, service, s);
	serv->cpcid  = get_cid_by_uuid16(service, 0x2a55);
	printf("Control Point CID%d\n" , serv->cpcid);
	return ;
}
