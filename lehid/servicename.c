#define L2CAP_SOCKET_CHECKED
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <usbhid.h>
#include <string.h>
#include <dev/usb/usbhid.h>
#include <bluetooth.h>
#include <uuid.h>
#include <sqlite3.h>
#include "sql.h"
#include "gatt.h"

#define MAX_ATTRIBUTE_LEN 512

extern uuid_t uuid_base;
struct serviceent{
	uint16_t uuid;
	char *name;
} srvent[]={
	{ 0x1800,"GAP"},
	{ 0x1801,"GATT"},
	{ 0x1802,"IAS"},
	{ 0x1803,"LLS"},
	{ 0x1804,"TPS"},
	{ 0x1805,"CTS"},
	{ 0x1806,"RTUS"},
	{ 0x1807,"NDCS"},
	{ 0x1808,"GLS"},
	{ 0x1809,"HTS"},
	{ 0x180a,"DIS"},
	{ 0x180d,"HRS"},
	{ 0x180e,"PASS"},
	{ 0x180f,"BAS"},
	{ 0x1812,"HID"},
	{ 0x1813,"ScPS"},	
	{ 0x1814,"RCS"},
	{ 0, NULL}
};
void install_service_name_table()
{
	sqlite3_stmt *stmt;
	struct serviceent *e;
	uuid_t uuid;
	int error ;
	
	stmt = get_stmt("INSERT INTO service_name (uuid, name) VALUES ($1 , $2) ");
	for(e = srvent; e->name != NULL; e++){
		uuid = uuid_base;
		uuid.time_low = e->uuid;
		sqlite3_bind_blob(stmt, 1, &uuid,  sizeof(uuid), SQLITE_TRANSIENT);
		sqlite3_bind_text(stmt, 2, e->name, strlen(e->name), SQLITE_STATIC);
		error = sqlite3_step(stmt);
		sqlite3_reset(stmt);
	}
	sqlite3_finalize(stmt);
	
}
