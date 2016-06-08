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
#include "att.h"
#include "gatt.h"
#include <sqlite3.h>
#include <getopt.h>
#include "sql.h"
#include "service.h"
#include "uuidbt.h"

extern uuid_t uuid_base;
struct dis_service{
	int dummy;
};
void dis_init(struct service *service, int s);

static struct service_driver dis_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = UUID16(0x180a),
	.init = dis_init,
	.notify = NULL
};
			    
void dis_init(struct service *service, int s)
{
	unsigned char buf[40];
	int len;
	int error;
	struct dis_service *serv;
	int cid;
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	
	printf("DIS:%d\n",  service->service_id);
	cid = get_cid_by_uuid16(service, 0x2a23);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("SystemID %x %x\n", (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|
		 buf[3],(buf[4]<<24)|(buf[5]<<16)|(buf[6]<<8)|buf[7]);
	  
	}
	cid = get_cid_by_uuid16(service, 0x2a24);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("Model No %s\n", buf);
	}
	cid = get_cid_by_uuid16(service, 0x2a25);	
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("Serial Number %s\n", buf);
	}
	cid = get_cid_by_uuid16(service, 0x2a26);	
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("Model Number %s\n", buf);
	}
	cid = get_cid_by_uuid16(service, 0x2a27);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("Hardware Revision %s\n", buf);
	}
	cid = get_cid_by_uuid16(service, 0x2a28);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("Software Revision %s\n", buf);
	}
	cid = get_cid_by_uuid16(service, 0x2a29);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  buf[len] = 0;
	  printf("Manifacture Name %s\n", buf);
	}
	cid = get_cid_by_uuid16(service, 0x2a2a);
	if(cid != -1){
	  int i;
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  printf("IEEE11073 DATA-");
	  for(i = 0; i < len ; i++){
	    if((i&7)==0){
	      printf("\n%04x:", i);
	    }
	    printf("%02x ", buf[i]);
	  }
	  printf("\n");	  
	}
	cid = get_cid_by_uuid16(service, 0x2a50);
	if(cid != -1){
	  len = le_char_read(s, cid, buf, sizeof(buf), 0);
	  printf("PnPID %02x %04x %04x %04x\n",buf[0], buf[1]|buf[2]<<8, buf[3]|buf[4]<<8,
		 buf[5]|buf[6]<<8);
	}

	return ;
}
