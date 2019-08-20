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
struct hrp_service{
	int location_cid;
	int measurement_cid;
	int cpoint_cid;
};
void hrp_notify(void *sc, int charid, unsigned char *buf, size_t len);
void hrp_service_init(struct service *service, int s);

struct service_driver hrp_driver __attribute__((used)) __attribute((section("driver"))) =
{
	.uuid = UUID16(0x180d),
	.init = &hrp_service_init,
	.notify = &hrp_notify,
};
void hrp_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	int i;
	printf("%zu\n", len);
	for(i = 0 ; i < len ; i++){
		printf("%02x ", buf[i]);
	}
	printf("\n");
	
}
void hrp_service_init(struct service *service, int s)
{
	int cid;
	struct hrp_service *serv;
	unsigned char buf[40];
	int len;
	
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	
	printf("HRP:%d\n",  service->service_id);
	//Get Measurement point	
	serv->location_cid = get_cid_by_uuid16(service, 0x2a38);

	if(serv->location_cid != -1){
		char *pos[] = {"Other", "Chest", "Wrist", "Finger",
			       "Hand", "Ear Lobe", "Foot"};
		len = le_char_read(s, serv->location_cid, buf, sizeof(buf), 0);
		if(len >= 1){
			printf("Position: %s\n", (buf[0] < (sizeof(pos)/ sizeof(*pos))) ? pos[buf[0]] : "Invalid");
		}

	}
	serv->measurement_cid = get_cid_by_uuid16(service, 0x2a37);
	if(serv->measurement_cid != -1){
		register_notify(serv->measurement_cid, service, s);		
	}else{
		printf("Measurement CID NOT FOUND\n");
		return;
	}
	serv->cpoint_cid = get_cid_by_uuid16(service, 0x2a39);
	if(serv->cpoint_cid == -1){
		printf("Control Point not found\n");
	}
	
	return ;
}
