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
#include <usbhid.h>
#include <dev/usb/usbhid.h>
#include "hogp.h"
#include "uuidbt.h"
#include "omron.h"
#include "notify.h"

extern uuid_t uuid_base;
struct omron_sensor_service{
	int ldata_cid;
	int lpage_cid;
	int rpage_cid;
	int rflag_cid;
	int rdata_cid;
	int ev_cid;
	sqlite3 *db;
	sqlite3_stmt *insenvrecord;
	sqlite3_stmt *readlastpage;
};
void omron_sensor_init(struct service *service, int s);
void omron_sensor_notify(void *sc, int charid, unsigned char *buf, size_t len);
static struct service_driver omron_sensor_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = OMRONID(0x3000),
	.init =omron_sensor_init,
	.notify = omron_sensor_notify
};
void omron_sensor_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	struct omron_sensor_service *serv = sc;
	int i;
	if(serv->ldata_cid == charid){
		printf("Latest data\n");
	}else if(serv->ev_cid == charid){
		printf("Event Occured\n");
		for(i = 2; i < 11; i++){
			printf(" %02x ", buf[i]);
		}
	}
	
}
static void print_record(unsigned char *buf)
{
	double temp, wet, lx, uv, prs, db, uc, heat, volt;
	int16_t st;
#define READSHORT(x) (buf[(x)]|buf[(x)+1]<<8)
	st = READSHORT(1);
	temp = st/100.;
	st = READSHORT(3);
	wet = st/100.;
	st = READSHORT(5);		
	lx = st;
	st = READSHORT(7);
	uv = st/100.;
	st = READSHORT(9);
	prs = st/10.;
	st = READSHORT(11);
	db = st/100.;
	st = READSHORT(13);
	uc = st/100.;
	st = READSHORT(15);
	heat = st/100.;
	st = READSHORT(17);
	volt = st;
#undef READSHORT		
	printf("%gC, %g %% %g lx %g uv %g hPa, %g db, Unconfort %g\n",
	       temp, wet, lx, uv, prs, db, uc);
	printf("heat %g C %g mV\n", heat, volt);
}
/*
static char *schema[] =
{
 "CREATE TABLE envrecord(id INTEGER PRIMARY KEY,time DATETIME, page INTEGER, row INTEGER, temp REAL, wet REAL, lux REAL, uv REAL, pressure REAL, db REAL, unconfort REAL, heat REAL, volt REAL);",
 "CREATE TABLE lastpage(time DATETIME, interval INTEGER, page INTEGER, row INTEGER);",
};
*/
void omron_sensor_init(struct service *service, int s)
{
	unsigned char buf[40];
	int len;
	int error;
	struct omron_sensor_service *serv;
	int cid;
	time_t curtime;
	int curpage;
	int i;
	char *errmsg;
	int pageno;
		
	serv = malloc(sizeof(*serv));

	service->sc = serv;
	uuid_t uuid;
	omron_id(0x3001, &uuid);
#if 0
	sqlite3_open_v2("omron.db", &serv->db, SQLITE_OPEN_READWRITE|
			SQLITE_OPEN_CREATE, NULL);
	for(i = 0; schema[i] != NULL; i++){
		error = sqlite3_exec(serv->db, schema[i], NULL, NULL, &errmsg);
		if (err != SQLITEOK){
			printf("%s\n", errmsg);
		}
	}

	sqlite3_prepare_v2(serv->db, "INSERT INTO envrecord(time, page, row, temp, wet, lux, uv, pressure, db, unconfort, heat, volt) VALUES(datetime($1,'unixepoch'), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)");
#endif		
	printf("SENSOR:%d\n",  service->service_id);
	cid = get_cid_by_uuid(service, &uuid);
	if(cid == -1){
		return;
	}
	serv->ldata_cid = cid;
	le_char_read(s, serv->ldata_cid, buf, sizeof(buf), 1);
	print_record(buf);
	omron_id(0x3002, &uuid);
	
	cid = get_cid_by_uuid(service, &uuid);
	if(cid == -1){
		return;
	}
	{
		time_t t;
		int intv;
		int line;
		char fmtbuf[50];
		serv->lpage_cid = cid;
		le_char_read(s, cid, buf, sizeof(buf), 1);
		t = buf[0]|(buf[1]<<8)|(buf[2]<<16)|(buf[3]<<24);
		intv = buf[4]|(buf[5]<<8);
		pageno = buf[6]|(buf[7]<<8);
		line = buf[8];
		ctime_r(&t, fmtbuf);
		printf("record %d %d %d %s\n", pageno, intv, line, fmtbuf);
	}
	omron_id(0x3003, &uuid);
	cid = get_cid_by_uuid(service, &uuid);	
	if(cid == -1){
		return;
	}
	serv->rpage_cid = cid;
	omron_id(0x3004, &uuid);
	cid = get_cid_by_uuid(service, &uuid);	
	if(cid == -1){
		return;
	}
	serv->rflag_cid = cid;
	len = le_char_read(s, cid, buf, sizeof(buf), 1);

	omron_id(0x3005, &uuid);
	cid = get_cid_by_uuid(service, &uuid);
	if(cid == -1){
		return;
	}
	serv->rdata_cid = cid;
	{
		time_t t;		
		int i,j;
		char fmtbuf[50];		
		for(i = pageno-200; i <=pageno; i++){
			printf("A\n");
			buf[0] = i&0xff;
			buf[1] = (i>>8)&7;
			buf[2] = 12;
			le_char_write(s, serv->rpage_cid, buf, 3, 0);
			for(j=0; j < 2; j++){
				le_char_read(s,serv->rflag_cid, buf, sizeof(buf), 1);
				if(buf[0] == 1){
					t = buf[1]|(buf[2]<<8)|(buf[3]<<16)|
						(buf[4]<<24);
					
					ctime_r(&t, fmtbuf);
					printf("%s\n", fmtbuf);
					break;
				}
			}
			if(j == 2)
				break;
			while(1){
				le_char_read(s, serv->rdata_cid, buf, sizeof(buf), 1);
				print_record(buf);
				if(buf[0] == 0){
					break;
				}
				
			}
		}
	}
        fflush(stdout);
	omron_id(0x3006, &uuid);
	cid = get_cid_by_uuid(service, &uuid);
			   if(cid != -1){
	  return;
	}
			   
	serv->ev_cid = cid;
	register_notify(serv->ldata_cid, service, s);
	register_notify(serv->ev_cid, service, s);	
	return ;
}
