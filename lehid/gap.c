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
#include <usbhid.h>
#include <dev/usb/usbhid.h>
#include "hogp.h"
#include "uuidbt.h"

extern uuid_t uuid_base;
struct gap_service{
	int dummy;
};
void gap_init(struct service *service, int s);

static struct service_driver gap_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = UUID16(0x1800),
	.init = gap_init,
	.notify = NULL
};
			    
void gap_init(struct service *service, int s)
{
	unsigned char buf[40];
	int len;
	int error;
	struct gap_service *serv;
	int cid;
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	
	printf("GAP:%d\n",  service->service_id);
	cid = get_cid_by_uuid16(service, 0x2a00);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("Device Name  %s\n", buf);
	}
	cid = get_cid_by_uuid16(service, 0x2a01);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  printf("Apperance  %d\n", buf[0]|buf[1]<<8);
	}
	cid = get_cid_by_uuid16(service, 0x2a02);	
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  printf("Peripheral Privacy Flag  %d\n", buf[0]);
	}
	cid = get_cid_by_uuid16(service, 0x2a03);	
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 1);
	  if(len != -1)
	    printf("reconnection_address %x:%x:%x:%x:%x:%x\n", buf[5],buf[4],
		 buf[3],buf[2],buf[1],buf[0]);
	}
	cid = get_cid_by_uuid16(service, 0x2a04);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  printf("Connection Parameters %d %d %d\n", buf[0]|buf[1]<<8,
		 buf[2]|buf[3]<<8, buf[4]|buf[5]<<8);
	}

	return ;
}
