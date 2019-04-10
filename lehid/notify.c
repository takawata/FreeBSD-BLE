#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
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
#include "uuidbt.h"
#include <sqlite3.h>
#include <getopt.h>
#include "sql.h"
#include "service.h"
#include "att.h"
#include "notify.h"

struct notify_dispatcher
{
	uint16_t handle;
	int cid;
	int property;
	struct service *serv;
}*dispatcher;
static int numdispatcher;

int register_notify(int cid, struct service *serv, int s)
{
	static sqlite3_stmt *queryhandle;
	struct notify_dispatcher *d;
	unsigned char buf[50];
	uuid_t uuid;

	if(queryhandle == NULL)
		queryhandle = get_stmt("SELECT handle,property from ble_attribute INNER JOIN ble_chara ON value_attribute_id = attribute_id where chara_id = $1;");
	if(queryhandle == NULL){
		printf("QUERYHANDLE\n" );
		return -1;
	}
	numdispatcher++;
	dispatcher = realloc(dispatcher, numdispatcher*(sizeof(*dispatcher)));
	if(dispatcher == NULL){
		printf("ENOMEM\n");
		return -1;
	}
	d = &dispatcher[numdispatcher -1];
	d->cid = cid;
	d->serv =serv;
	sqlite3_bind_int(queryhandle, 1, cid);
	sqlite3_step(queryhandle);
	d->handle = sqlite3_column_int(queryhandle, 0);
	d->property = sqlite3_column_int(queryhandle, 1);

	sqlite3_reset(queryhandle);
	
	buf[0] = ((d->property&GATT_PERM_NOTIFY)?1:0)|
		((d->property&GATT_PERM_INDICATE)?2:0);
	buf[1] = 0;
	btuuid16(0x2902,&uuid);
	le_char_desc_write(s, cid, &uuid, buf, 2, 0);
	
	return 0;
}

int notify_handler(unsigned char *buf, int len, int isindicate, int s)
{
	int i;
	struct service *serv;
	for(i=0; i < numdispatcher; i++){
		if(dispatcher[i].handle == (buf[0]|(buf[1]<<8))){
			serv = dispatcher[i].serv;
			if(serv->driver != NULL && serv->driver->notify!=NULL
			   && serv->sc != NULL)
				serv->driver->notify(serv->sc,
						     dispatcher[i].cid,
						     buf, len);
		}
	}
	return 0;
}
