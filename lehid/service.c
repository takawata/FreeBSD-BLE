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
#include "gatt.h"
#include "uuidbt.h"
#include <sqlite3.h>
#include <getopt.h>
#include "sql.h"
#include "service.h"
#include "att.h"

/*
 * Linker set process. 
 * Put driver information structure in ELF section named "driver".
 * This module process the section and call initialize routine and
 * register event handlers.
 */



static int num_service;
struct service *service_ent;
struct default_service{
	uuid_t uuid;
};
void default_service_init(struct service *service, int s)
{
	static struct sqlite3_stmt *stmt;
	int chara_id;
	uuid_t uuid;
	char *str;
	uint32_t status;
	struct default_service *sc;
	sc = (struct default_service *)service->sc;
	uuid_to_string(&sc->uuid, &str, &status );
	printf("ID%d: %s\n", service->service_id, str);
	free(str);
	str = NULL;
	
	if(stmt == NULL)
		stmt = get_stmt("SELECT chara_id,uuid FROM ble_chara WHERE service_id = $1;");
	sqlite3_bind_int(stmt, 1, service->service_id);
	while(sqlite3_step(stmt) == SQLITE_ROW){
		chara_id = sqlite3_column_int(stmt, 0);
		my_column_uuid(stmt, 1, &uuid);
		uuid_to_string(&uuid, &str, &status );
		printf("%x %s\n", chara_id, str);
		free(str);
	}
	sqlite3_reset(stmt);
	return;
}
struct service_driver default_driver =
{
	.init = &default_service_init,
	.notify = NULL,
};



int attach_service(int s, int device_id )
{
	sqlite3_stmt *stmt;
	uuid_t uuid;
	int service_id;
	int i;
	int error;
	const void *ptr;
	struct default_service *dfs;
	extern struct service_driver __start_driver;
	extern struct service_driver __stop_driver;  
	struct service_driver *it;
	
	stmt = get_stmt("SELECT service_id,uuid from ble_service where device_id=$1;");
	num_service = 0;
	if(stmt == NULL){
		printf("STMT ERROR\n");
		return 0;
	}
	sqlite3_bind_int(stmt, 1, device_id);
	while(1){
		error = sqlite3_step(stmt);
		if(error != SQLITE_ROW)
			break;
		service_id = sqlite3_column_int(stmt, 0);
		error = my_column_uuid(stmt, 1, &uuid);
		if(error)
			printf("UUID column invalid\n");

		service_ent = realloc(service_ent,
				      sizeof(struct service)*(num_service+1));
		service_ent[num_service].service_id = service_id;
		service_ent[num_service].driver = &default_driver;
		dfs = service_ent[num_service].sc = malloc(sizeof(struct default_service));
		memcpy(&dfs->uuid, &uuid, sizeof(uuid));

		for(it=&__start_driver; it < &__stop_driver;it++){
			if(uuid_equal(&it->uuid, &uuid, NULL)){
				service_ent[num_service].driver = it;
				free(service_ent[num_service].sc);
				(service_ent[num_service].sc) = NULL;
			}
		}
		
		num_service++;

	}
	sqlite3_finalize(stmt);
	for(i = 0 ; i < num_service; i++){
		service_ent[i].driver->init(&service_ent[i], s);
	}

	return 0;
}
