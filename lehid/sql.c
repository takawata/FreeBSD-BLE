
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
#include <sqlite3.h>
#include "hccontrol.h"
#include "att.h"
#include "gatt.h"
#include <getopt.h>
#include "sql.h"
#include "uuidbt.h"

static char *schema[]={
	"CREATE TABLE ble_device (device_id INTEGER PRIMARY KEY,addrtype INTEGER, addr BLOB(6), last_attribute INTEGER,UNIQUE (addrtype, addr) ON CONFLICT REPLACE) ;",
	"CREATE TABLE ble_attribute(attribute_id INTEGER PRIMARY KEY, device_id INTEGER, handle INTEGER, uuid BLOB(16),cache BLOB, perm INTEGER,UNIQUE (device_id, handle) ON CONFLICT REPLACE) ;",
	"CREATE TABLE ble_service(service_id INTEGER PRIMARY KEY, device_id INTEGER, uuid BLOB(16), low_attribute_id INTEGER, high_attribute_id INTEGER,UNIQUE(device_id, low_attribute_id) ON CONFLICT REPLACE) ;",
	"CREATE TABLE ble_chara(chara_id INTEGER PRIMARY KEY, low_attribute_id INTEGER, high_attribute_id INTEGER, service_id INTEGER, value_attribute_id INTEGER, uuid BLOB(16), property INTEGER, UNIQUE(service_id, low_attribute_id) ON CONFLICT REPLACE ) ;",
	"CREATE TABLE service_name(uuid BLOB(16) PRIMARY KEY, name STRING);",
	"CREATE TABLE ble_include(include_id INTEGER PRIMARY KEY, service_id INTEGER, def_attribute_id INTEGER, low_attribute_id INTEGER, high_attribute_id INTEGER)",
	"CREATE TRIGGER update_ble_device AFTER INSERT ON ble_attribute\
	BEGIN \
		UPDATE ble_device SET last_attribute = new.attribute_id WHERE device_id = new.device_id; \
	END;",

	"CREATE TRIGGER insert_ble_service AFTER INSERT ON ble_attribute\
	WHEN new.uuid=(x'0028000000000010800000805F9B34FB') or new.uuid=(x'0128000000000010800000805F9B34FB')\
	BEGIN \
		UPDATE ble_chara SET high_attribute_id=new.attribute_id-1 WHERE \
			(service_id = (SELECT max(service_id) FROM ble_service) AND (chara_id = (SELECT max(chara_id) FROM ble_chara))); \
		UPDATE ble_service SET high_attribute_id=new.attribute_id-1 WHERE\
			(service_id = (SELECT max(service_id) FROM ble_service) AND device_id = new.device_id);\
		INSERT INTO ble_service (device_id, low_attribute_id) VALUES (new.device_id, new.attribute_id) ; \
	END;",
	"CREATE TRIGGER insert_ble_include AFTER INSERT ON ble_attribute\
	WHEN new.uuid=(x'0228000000000010800000805F9B34FB') \
	BEGIN \
		INSERT INTO ble_include  (service_id, def_attribute_id) \
        		VALUES ((SELECT max(service_id) FROM ble_service),\
		 new.attribute_id) ; \
        END;",
	"CREATE TRIGGER insert_ble_chara AFTER INSERT ON ble_attribute\
	WHEN new.uuid=(x'0328000000000010800000805F9B34FB') \
	BEGIN \
		UPDATE ble_chara SET high_attribute_id=new.attribute_id-1 WHERE \
			(service_id = (SELECT max(service_id) FROM ble_service) AND (chara_id = (SELECT max(chara_id) FROM ble_chara))); \
		INSERT INTO ble_chara  (service_id, low_attribute_id) \
        		VALUES ((SELECT max(service_id) FROM ble_service),\
		 new.attribute_id) ; \
        END;",
	NULL
};
static sqlite3 *thedb;
int open_db(char *dbname)
{
	return sqlite3_open_v2(dbname, &thedb, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
}

sqlite3_stmt *get_stmt(char *sql)
{
	sqlite3_stmt *stmt;
	int error;
	error = sqlite3_prepare_v2(thedb, sql,strlen(sql),
				   &stmt,  NULL);
	if(error != SQLITE_OK){
		return NULL;
	}
	return stmt;
}
void btuuid16_func(sqlite3_context *ctx, int count, sqlite3_value ** val)
{
	uint8_t buf[16];
	uuid_t uuid;
	btuuid16(sqlite3_value_int(val[0]), &uuid);
	uuid_enc_bt(buf, &uuid);
	sqlite3_result_blob(ctx, buf, sizeof(buf), SQLITE_TRANSIENT);
}

void create_uuid_func()
{

	sqlite3_create_function(thedb, "btuuid16", 1,
				SQLITE_UTF8|SQLITE_DETERMINISTIC,
				NULL, btuuid16_func, NULL, NULL);
#if 0	
	sqlite3_exec(thedb, "CREATE TABLE test(uuid BLOB(16));", NULL, NULL, &myerrmsg);
	//printf("%s\n", myerrmsg);
	sqlite3_exec(thedb, "INSERT INTO test VALUES (btuuid16(0x1234));", NULL, NULL, &myerrmsg);
	
	//printf("%s\n", myerrmsg);
#endif
}
void init_schema()
{
	int i = 0;
	int err;
	char *errmsg;
	for(i=0; schema[i] != NULL; i++){
		err = sqlite3_exec(thedb, schema[i], NULL, NULL, &errmsg);
#if 0		
		if(err != SQLITE_OK){
			printf("%s\n", errmsg);
		}
#endif		
	}
}
int end_attribute_probe(int device_id)
{
	const char chara_term[] = "UPDATE ble_chara SET high_attribute_id = (SELECT max(attribute_id) from ble_attribute) WHERE (service_id = (SELECT max(service_id) FROM ble_service) AND (chara_id = (SELECT max(chara_id) FROM ble_chara))); ";
	const char service_term[] = "UPDATE ble_service SET high_attribute_id=(SELECT max(attribute_id) from ble_attribute) WHERE (service_id = (SELECT max(service_id) FROM ble_service) AND device_id = (SELECT max(device_id) FROM ble_device));";
	const char commit_sql[] ="COMMIT TRANSACTION attribute_probe;";
	const char rollback_sql[] ="ROLLBACK TRANSACTION attribute_probe;";
	int error;
	char *errmsg;
	error = sqlite3_exec(thedb, chara_term, NULL, NULL, &errmsg);
	if(error != SQLITE_OK)
	{
		printf("%s\n", errmsg);
	}
	error = sqlite3_exec(thedb, service_term, NULL, NULL, &errmsg);
	if(error != SQLITE_OK)
	{
		printf("%s\n", errmsg);
	}

	printf("%s\n", service_term);
	error = sqlite3_exec(thedb, commit_sql, NULL, NULL, &errmsg);
	
	return error;
}

int get_latest_rowid()
{
	const char lastrow_sql[] ="SELECT last_insert_rowid();";
	static sqlite3_stmt *lastrowhandle = NULL;
	int row_id;
	if(lastrowhandle ==NULL)
		sqlite3_prepare_v2(thedb, lastrow_sql,sizeof(lastrow_sql),
				   &lastrowhandle,  NULL);
	
	sqlite3_step(lastrowhandle);
	row_id = sqlite3_column_int(lastrowhandle, 0);
	sqlite3_reset(lastrowhandle);
	
	return row_id;
}	


int create_attribute(int device_id, int handle, uuid_t *uuid)
{
	static sqlite3_stmt *createhandle = NULL;
	const char insert_sql[] ="INSERT INTO ble_attribute (device_id, handle, uuid) VALUES ($1, $2, $3);";
	if(createhandle ==NULL){
		sqlite3_prepare_v2(thedb, insert_sql, sizeof(insert_sql),
				   &createhandle, NULL);
	}
	sqlite3_bind_int(createhandle, 1, device_id);
	sqlite3_bind_int(createhandle, 2, handle);
	sqlite3_bind_blob(createhandle, 3, uuid, sizeof(*uuid), SQLITE_TRANSIENT);
	sqlite3_step(createhandle);
	sqlite3_reset(createhandle);

	return 0;
}

int search_device(int addrtype, bdaddr_t addr)
{
	static sqlite3_stmt *searchhandle = NULL;
	const char search_sql[]="SELECT device_id FROM ble_device where addrtype=$1 AND addr = $2;";
	int device_id = 0;
	int error;
	if(searchhandle ==NULL)
		error = sqlite3_prepare_v2(thedb,
					   search_sql,sizeof(search_sql),
					   &searchhandle,  NULL);

	sqlite3_bind_int(searchhandle, 1, addrtype);
	sqlite3_bind_blob(searchhandle, 2, &addr, sizeof(addr), SQLITE_TRANSIENT);
	if((error = sqlite3_step(searchhandle)) == SQLITE_ROW){
		printf("HOGEHOGE\n");
		device_id = sqlite3_column_int(searchhandle, 0);
		printf("DEVICE_ID %d\n", device_id);
	}
	sqlite3_reset(searchhandle);
	return device_id;
}
int create_device( int addrtype, bdaddr_t addr)
{
	static sqlite3_stmt *createhandle = NULL;

	const char insert_sql[]="INSERT INTO ble_device (addrtype, addr) VALUES ($1, $2);";
	
	int error;
	int device_id = 0;
	char * errmsg;
	const char transaction_sql[] ="BEGIN EXCLUSIVE TRANSACTION attribute_probe;";	
	if((device_id = search_device(addrtype, addr))!= 0){
		return device_id;
	}

	sqlite3_exec(thedb, transaction_sql, NULL, NULL, &errmsg);
	if(createhandle ==NULL)
		sqlite3_prepare_v2(thedb,insert_sql, sizeof(insert_sql),
				   &createhandle,
			NULL);
	
	sqlite3_bind_int(createhandle, 1, addrtype);
	sqlite3_bind_blob(createhandle, 2, &addr, sizeof(addr), SQLITE_TRANSIENT);
	
	error = sqlite3_step(createhandle);
	printf("%s\n", sqlite3_errstr(error));
	sqlite3_reset(createhandle);
	device_id = get_latest_rowid();
	
	return device_id;
}
