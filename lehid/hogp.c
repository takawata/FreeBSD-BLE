/*
 * hgop.c
 *
 * Copyright (c) 2016 Takanori Watanabe
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 * $FreeBSD$
 */
/*
 * Partly delived from

 * Copyright (c) 2006 Maksim Yevmenkin <m_evmenkin@yahoo.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * src/usr.sbin/bluetooth/bthidd/hid.c
 */


#include <sys/consio.h>
#include <sys/mouse.h>
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
#include "att.h"
#include "gatt.h"
#include <sqlite3.h>
#include <getopt.h>
#include "sql.h"
#include "service.h"
#include <usbhid.h>
#include <dev/usb/usbhid.h>
#include "uuidbt.h"
#include "hogp.h"
void hogp_init(struct service *service, int s);
void hogp_notify(void *sc, int charid, unsigned char *buf, int len);
#define HID_INFORMATION 0x2a4a 
#define HID_REPORT_MAP 0x2a4b
#define HID_CONTROL_POINT 0x2a4c
#define HID_REPORT 0x2a4d
#define PROTOCOL_MODE 0x2a4e
#define HID_BOOT_KEYBOARD 0x2a22
#define HID_BOOT_MOUSE 0x2432
#define REPORT_REFERENCE 0x2908
#define CLIENT_CONFIGURATION 0x2902

#define MAXRIDMAP 10
struct hogp_ridmap{
	int cid;
	int rid;
	int type;
};
struct hogp_service{
	unsigned char hidmap[512];
	report_desc_t desc;
	int nrmap;
	int cons;
	struct hogp_ridmap rmap[MAXRIDMAP];
};

static struct service_driver  hogp_driver __attribute__((section(("driver")))) __attribute__((used)) =
{
	.uuid = UUID16(0x1812),
	.init = hogp_init,
	.notify = hogp_notify,
};


static const char *
hid_collection_type(int32_t type)
{
	static char num[8];

	switch (type) {
	case 0: return ("Physical");
	case 1: return ("Application");
	case 2: return ("Logical");
	case 3: return ("Report");
	case 4: return ("Named_Array");
	case 5: return ("Usage_Switch");
	case 6: return ("Usage_Modifier");
	}
	snprintf(num, sizeof(num), "0x%02x", type);
	return (num);
}

static void
dumpitem(const char *label, struct hid_item *h)
{
	//if ((h->flags & HIO_CONST) && !verbose)
	//return;
	printf("%s rid=%d size=%d count=%d page=%s usage=%s%s%s", label,
	       h->report_ID, h->report_size, h->report_count,
	       hid_usage_page(HID_PAGE(h->usage)),
	       hid_usage_in_page(h->usage),
	       h->flags & HIO_CONST ? " Const" : "",
	       h->flags & HIO_VARIABLE ? "" : " Array");
	printf(", logical range %d..%d",
	       h->logical_minimum, h->logical_maximum);
	if (h->physical_minimum != h->physical_maximum)
		printf(", physical range %d..%d",
		       h->physical_minimum, h->physical_maximum);
	if (h->unit)
		printf(", unit=0x%02x exp=%d", h->unit, h->unit_exponent);
	printf("\n");
}

void hid_dump_item(report_desc_t rd)
{
	hid_data_t hd;
	hid_item_t it;
	int res;


	hd = hid_start_parse(rd, ~0, -1);
	for (hd = hid_start_parse(rd, ~0, -1); hid_get_item(hd, &it); ) {
		switch(it.kind){
		case hid_collection:
			printf("Collection type=%s page=%s usage=%s\n",
			       hid_collection_type(it.collection),
			       hid_usage_page(HID_PAGE(it.usage)),
			       hid_usage_in_page(it.usage));
			break;
		case hid_endcollection:
			printf("End collection\n");
			break;
		case hid_input:
			dumpitem("Input  ", &it);
			break;
		case hid_output:
			dumpitem("Output ", &it);
			break;
		case hid_feature:
			dumpitem("Feature", &it);
			break;
		}
	}
}
/*
 * Create temporary table of services included.
 */
void hogp_service_include(struct service *service)
{
	sqlite3_stmt *stmt;
	stmt = get_stmt("CREATE TEMPORARY TABLE iservice AS select ble_service.service_id from ble_service INNER JOIN ble_include ON ble_service.low_attribute_id = ble_include.low_attribute_id where ble_include.service_id = $1;");
	sqlite3_bind_int(stmt,1,service->service_id);
	printf("STMT1%p\n", stmt);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = get_stmt("INSERT INTO iservice VALUES ($1);");
	sqlite3_bind_int(stmt, 1, service->service_id);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
}

/*
 * Create temporaly table of characteristic UUID 
 * which should be treated as REPORT.
 */
void hogp_ext_ref(struct service *service, int mapcid, int s)
{
	sqlite3_stmt *stmt1,*stmt2;
	uuid_t uuid;
	unsigned char buf[50];
	int len;
	int attr_id;

	stmt1 = get_stmt("CREATE TEMPORARY TABLE reftable(uuid BLOB(16)) ;");
	sqlite3_step(stmt1);
	sqlite3_finalize(stmt1);

	stmt1 = get_stmt("INSERT INTO reftable VALUES ($1);");
	/*HID report */
	btuuid16(HID_REPORT, &uuid);
	sqlite3_bind_blob(stmt1, 1, &uuid, sizeof(uuid), SQLITE_TRANSIENT);
	sqlite3_step(stmt1);
	sqlite3_reset(stmt1);
	/*Read External Report Reference and insert into table*/
	btuuid16(0x2907, &uuid);
	stmt2 = get_stmt("SELECT attribute_id FROM ble_attribute , (SELECT low_attribute_id, high_attribute_id from ble_chara WHERE chara_id=$1) AS c WHERE (attribute_id BETWEEN c.low_attribute_id AND c.high_attribute_id) AND uuid = $2 ;");
	sqlite3_bind_int(stmt2, 1 , mapcid);
	sqlite3_bind_blob(stmt2, 2, &uuid, sizeof(uuid), SQLITE_TRANSIENT);
	while(sqlite3_step(stmt2) == SQLITE_ROW){
		attr_id =sqlite3_column_int(stmt2, 0);
		len = le_att_read(s, attr_id, buf, sizeof(buf), 0);
		if(len == 2){
			btuuid16(buf[0]|buf[1]<<8, &uuid);
		}else if(len== 16){
			memcpy(&uuid, buf, sizeof(uuid));
		}
		sqlite3_bind_blob(stmt1, 1, &uuid, sizeof(uuid), SQLITE_TRANSIENT);
		sqlite3_step(stmt1);
		sqlite3_reset(stmt1);
	}
	sqlite3_finalize(stmt1);
	sqlite3_finalize(stmt2);

}
void hogp_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int cid;
	int len;
	hid_init(NULL);
	int error;
	sqlite3_stmt *stmt;
	struct hogp_service *serv;
	service->sc = serv = malloc(sizeof(*serv));
	serv->desc = NULL;
	printf("HOGP:%d\n", service->service_id);
	hogp_service_include(service);


	stmt = get_stmt("SELECT chara_id from ble_chara where service_id = $1 and uuid = $2;");
	btuuid16(HID_INFORMATION, &uuid);
	sqlite3_bind_int(stmt, 1, service->service_id);
	sqlite3_bind_blob(stmt, 2, &uuid, sizeof(uuid), SQLITE_TRANSIENT);
	
	if((error = sqlite3_step(stmt)) != SQLITE_ROW){
		fprintf(stderr, "HID Information not found %d\n", error);
		return ;
	}
	cid = sqlite3_column_int(stmt, 0);
	sqlite3_reset(stmt);
	len = le_char_read(s, cid, buf, sizeof(buf), 0);
	if(len < 0){
		fprintf(stderr, "Cannot read HID Info %d\n", len);
	}
	printf("HID Version:%x Country Code %d FLAG:%x\n", buf[0]|(buf[1]<<8),
	       buf[2], buf[3]);
	serv->cons = open("/dev/consolectl", O_RDWR);
	printf("%d\n", serv->cons);
	btuuid16(HID_REPORT_MAP, &uuid);	
	sqlite3_bind_int(stmt, 1, service->service_id);
	sqlite3_bind_blob(stmt, 2, &uuid, sizeof(uuid), SQLITE_TRANSIENT);
	
	if((error = sqlite3_step(stmt)) != SQLITE_ROW){
		fprintf(stderr, "HID REPORT MAP not found %d\n", error);
		return ;
	}
	cid = sqlite3_column_int(stmt, 0);
	sqlite3_reset(stmt);
	hogp_ext_ref(service, cid, s);
	len = le_char_read(s, cid, serv->hidmap, sizeof(serv->hidmap), 0);
	if(len < 0){
		fprintf(stderr, "Cannot read REPORT MAP %d \n", len);
		return;
	}

	serv->desc = hid_use_report_desc(serv->hidmap, len);	
	hid_dump_item(serv->desc);
	sqlite3_finalize(stmt);

	/*report characteristics from associated services*/
	stmt = get_stmt("SELECT chara_id FROM ble_chara INNER JOIN reftable ON ble_chara.uuid=reftable.uuid INNER JOIN iservice ON iservice.service_id=ble_chara.service_id;");
	serv->nrmap = 0;
	while((error = sqlite3_step(stmt)) == SQLITE_ROW){
		int report_type;
		cid = sqlite3_column_int(stmt, 0);
		btuuid16(REPORT_REFERENCE, &uuid);
		le_char_desc_read(s, cid, &uuid, buf, sizeof(buf), 0);
		serv->rmap[serv->nrmap].cid = cid;
		serv->rmap[serv->nrmap].rid = buf[0];
		report_type = serv->rmap[serv->nrmap].type = buf[1];		
		printf("CharID: %x ReportID:%d ReportType%d\n", cid,
		       buf[0], buf[1]);
		serv->nrmap++;
		if(report_type == 1){
			buf[0] = 1;
			buf[1] = 0;
			btuuid16(CLIENT_CONFIGURATION,&uuid);
			le_char_desc_write(s, cid, &uuid, buf, 2, 0);
		}
	}
	sqlite3_finalize(stmt);
	printf("%d\n", serv->nrmap);
	stmt = get_stmt("DROP TABLE iservice;");
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	stmt = get_stmt("DROP TABLE reftable;");
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	return;
}
void hogp_process_report(struct hogp_service *serv, unsigned char *buf)
{
	int rid = buf[0];
	int32_t	usage, page, val,
		mouse_x, mouse_y, mouse_z, mouse_butt,
		mevents, kevents, i;
	hid_data_t d;
	hid_item_t h;
	mouse_x = mouse_y = mouse_z = mouse_butt = mevents = kevents = 0;
	if(serv->desc == NULL)
	  return ;
  	for (d = hid_start_parse(serv->desc, 1 << hid_input, -1);
	     hid_get_item(d, &h) > 0; ) {
		if ((h.flags & HIO_CONST) || (h.report_ID != rid) ||
		    (h.kind != hid_input))
			continue;
		page = HID_PAGE(h.usage);		
		val = hid_get_data(buf, &h);
		
		/*
		 * When the input field is an array and the usage is specified
		 * with a range instead of an ID, we have to derive the actual
		 * usage by using the item value as an index in the usage range
		 * list.
		 */
		if ((h.flags & HIO_VARIABLE)) {
			usage = HID_USAGE(h.usage);
		} else {
			const uint32_t usage_offset = val - h.logical_minimum;
			usage = HID_USAGE(h.usage_minimum + usage_offset);
		}
		
		switch (page) {
		case HUP_GENERIC_DESKTOP:
			switch (usage) {
			case HUG_X:
				mouse_x = val;
				mevents ++;
				break;

			case HUG_Y:
				mouse_y = val;
				mevents ++;
				break;

			case HUG_WHEEL:
				mouse_z = -val;
				mevents ++;
				break;

			case HUG_SYSTEM_SLEEP:
				if (val)
					printf("SLEEP BUTTON PRESSED\n");
				break;
			}
			break;

		case HUP_KEYBOARD:
			kevents ++;
			printf("Key value %d\n", val);
#if 0
			if (h.flags & HIO_VARIABLE) {
				if (val && usage < kbd_maxkey())
					bit_set(s->keys1, usage);
			} else {
				if (val && val < kbd_maxkey())
					bit_set(s->keys1, val);

				for (i = 1; i < h.report_count; i++) {
					h.pos += h.report_size;
					val = hid_get_data(data, &h);
					if (val && val < kbd_maxkey())
						bit_set(s->keys1, val);
				}
			}
#endif			
			break;

		case HUP_BUTTON:
			if (usage != 0) {
				if (usage == 2)
					usage = 3;
				else if (usage == 3)
					usage = 2;
				
				mouse_butt |= (val << (usage - 1));
				mevents ++;
			}
			break;

		case HUP_CONSUMER:
			if (!val)
				break;

			switch (usage) {
			case HUC_AC_PAN:
				/* Horizontal scroll */
				if (val < 0)
					mouse_butt |= (1 << 5);
				else
					mouse_butt |= (1 << 6);

				mevents ++;
				val = 0;
				break;

			case 0xb5: /* Scan Next Track */
				val = 0x19;
				break;
				
			case 0xb6: /* Scan Previous Track */
				val = 0x10;
				break;
				
			case 0xb7: /* Stop */
				val = 0x24;
				break;
				
			case 0xcd: /* Play/Pause */
				val = 0x22;
				break;
				
			case 0xe2: /* Mute */
				val = 0x20;
				break;

			case 0xe9: /* Volume Up */
				val = 0x30;
				break;
				
			case 0xea: /* Volume Down */
				val = 0x2E;
				break;
				
			case 0x183: /* Media Select */
				val = 0x6D;
				break;
				
			case 0x018a: /* Mail */
				val = 0x6C;
				break;
				
			case 0x192: /* Calculator */
				val = 0x21;
				break;
				
			case 0x194: /* My Computer */
				val = 0x6B;
				break;
				
			case 0x221: /* WWW Search */
				val = 0x65;
				break;
				
			case 0x223: /* WWW Home */
				val = 0x32;
				break;

			case 0x224: /* WWW Back */
				val = 0x6A;
				break;

			case 0x225: /* WWW Forward */
				val = 0x69;
				break;

			case 0x226: /* WWW Stop */
				val = 0x68;
				break;

			case 0x227: /* WWW Refresh */
				val = 0x67;
				break;

			case 0x22a: /* WWW Favorites */
				val = 0x66;
				break;
				
			default:
				val = 0;
				break;
			}
			
			/* XXX FIXME - UGLY HACK */
			if (val != 0) {
				printf("Consumer Page:%d\n", val);
#if 0				
				if (hid_device->keyboard) {
					int32_t	buf[4] = { 0xe0, val,
							   0xe0, val|0x80 };
					
					assert(s->vkbd != -1);
					write(s->vkbd, buf, sizeof(buf));
				} else
					syslog(LOG_ERR, "Keyboard events " \
					       "received from non-keyboard " \
					       "device %s. Please report",
					       bt_ntoa(&s->bdaddr, NULL));
#endif							
			}

			break;
			
		case HUP_MICROSOFT:
			switch (usage) {
			case 0xfe01:
#if 0				
				if (!hid_device->battery_power)
					break;
#endif				
				printf("Battery value:%d\n", val);
			}
			break;
		}
	}
	hid_end_parse(d);
	if (mevents > 0) {
		struct mouse_info	mi;

		mi.operation = MOUSE_ACTION;
		mi.u.data.x = mouse_x;
		mi.u.data.y = mouse_y;
		mi.u.data.z = mouse_z;
		mi.u.data.buttons = mouse_butt;

		if (ioctl(serv->cons, CONS_MOUSECTL, &mi) < 0)
			fprintf(stderr, "%s %d\n",
				strerror(errno), errno);
	}

	
}
void hogp_notify(void *sc, int charid, unsigned char *buf, int len)
{

	int i;
	struct hogp_service *serv = sc;
	int rid;
	int page;
	rid = -1;
	for(i=0; i< serv->nrmap; i++){
		if(charid == serv->rmap[i].cid){
			rid = serv->rmap[i].rid;
			break;
		}
	}
	buf[1] = rid;
	hogp_process_report(serv, buf+1);
}
