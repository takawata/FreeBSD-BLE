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

static int num_service;
struct lightbulb_service{
	uuid_t uuid;
};

// f0:c7:7f:93:ec:70

void lightbulb_service_init(struct service *service, int s)
{
	static struct sqlite3_stmt *stmt;
	int chara_id;
	uuid_t uuid;
	char *str;
	uint32_t status;
	unsigned char buf[30];
	int len;
	int i;
	int property;
	struct lightbulb_service *sc;
	sc = (struct lightbulb_service *)service->sc;
	uuid_to_string(&sc->uuid, &str, &status );
	printf("ID%d: %s\n", service->service_id, str);
	free(str);
	str = NULL;
	
	if(stmt == NULL)
		stmt = get_stmt("SELECT chara_id,uuid,property FROM ble_chara WHERE service_id = $1;");
	sqlite3_bind_int(stmt, 1, service->service_id);
	while(sqlite3_step(stmt) == SQLITE_ROW){
		chara_id = sqlite3_column_int(stmt, 0);
		my_column_uuid(stmt, 1, &uuid);
		property = sqlite3_column_int(stmt, 2);		
		uuid_to_string(&uuid, &str, &status );
		printf("%x %s ", chara_id, str);
		if(property&GATT_PERM_READ)
			printf("read ");
		if(property&GATT_PERM_WRITE)
			printf("write ");
		if(property&GATT_PERM_NOTIFY)
			printf("notify ");
		printf("\n");
		if(property&GATT_PERM_READ){
			len = le_char_read(s, chara_id, buf, sizeof(buf), 1);
			for(i = 0; i < len; i++){
				printf(" %02x", buf[i]);
			}
			printf("\n");
		}else{
			printf("WRITE ONLY\n");
		}
		free(str);
	}
	sqlite3_reset(stmt);
	chara_id = get_cid_by_uuid16(service, 0xffb1);
	buf[0] = 0;
	buf[1] = 1;
	buf[2] = 1;
	buf[3] = 21;
	le_char_write(s, chara_id, buf, 4, 0);
	chara_id = get_cid_by_uuid16(service, 0xffb9);
	buf[0] = -1;
	buf[1] = -52;
	buf[2] = -103;
	buf[4] = 102;
	buf[5]  =102;
	buf[6] = -103;
	buf[7] = -52;
	le_char_write(s, chara_id, buf, 8, 0);	
	chara_id = get_cid_by_uuid16(service, 0xffba);
	buf[0] = -1;
	buf[1] = -52;
	buf[2] = -103;
	buf[4] = 102;
	buf[5]  =102;
	buf[6] = -103;
	buf[7] = -52;
	le_char_write(s, chara_id, buf, 8, 0);	

	chara_id = get_cid_by_uuid16(service, 0xffbb);
	buf[0] = -1;
	buf[1] = -52;
	buf[2] = -103;
	buf[4] = 102;
	buf[5]  =102;
	buf[6] = -103;
	buf[7] = -52;
	le_char_write(s, chara_id, buf, 8, 0);	
	return;
}

struct service_driver lightbulb_driver __attribute__((section(("driver")))) __attribute__((used))=
{
	.uuid = UUID16(0xffb0),
	.init = &lightbulb_service_init,
	.notify = NULL,
};


