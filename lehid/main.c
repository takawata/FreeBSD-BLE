/*
 * main.c
 *
 * Copyright (c) 2015 Takanori Watanabe
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

uuid_t uuid_base;
int timeout = 30;


static int mtu = 23;
int num_handle = 0;
static unsigned char sentcmd[12];
int le_write(int s, unsigned char *buf, size_t siz)
{
	memcpy(sentcmd, buf, sizeof(sentcmd));
	return write(s, buf, siz);
}

int le_read(int s,unsigned char *buf,size_t buflen)
{
	int i;
	int len;
	int ret = 0;
	uint16_t handle,chandle;
	
	for(;;){
		if((len = read(s, buf, buflen)) <=0 ){
			return -1;
		}
		ret = len;

		switch(buf[0]){
		case ATT_OP_ERR:
			if(buf[1] != sentcmd[0]){
				printf("ERROR not match\n");
			}
			printf("OP %x: Handle %04x CODE %x\n",
			buf[1], buf[2]|(buf[3]<<8), buf[4]);
			ret = -1;
			goto end;
		case ATT_OP_READ_RES:
			for(i=1; i < len;i++){
				printf("%02x ", buf[i]);
			}
			printf("\n");
			if(sentcmd[0] != ATT_OP_READ_REQ){
				printf("SPRIOUS READ\n");
				ret = -1;
			}		  
			goto end;
		case ATT_OP_FIND_INFO_RES:
			if(sentcmd[0] != ATT_OP_FIND_INFO_REQ){
				printf("SPRIOUS FINDRES\n");
				ret = -1;
			}
			goto end;
		case ATT_OP_MTU_RES:
			if(sentcmd[0] != ATT_OP_MTU_REQ){
				printf("SPRIOUS MTU\n");
				ret = -1;
			}
			mtu = buf[1]|(buf[2]<<8);
			goto end;
		case ATT_OP_READ_BLOB_RES:
			if(sentcmd[0] != ATT_OP_READ_BLOB_REQ){
				printf("SPRIOUS BLOBRES\n");
				ret = -1;
			}
			goto end;
		case ATT_OP_NOTIFY:
			notify_handler(buf+1, len);
			break;
		case ATT_OP_INDICATE:
			printf("INDICATE\n");
			break;
			
		case ATT_OP_FIND_INFO_REQ:
			printf("FIND_INFO\n");
			break;
		case ATT_OP_FIND_TYPE_REQ:
			printf("FIND_TYPE\n");
			for(i=1; i < len;i++){
				printf("%02x ", buf[i]);
			}
			printf("\n");
			break;
		case ATT_OP_WRITE_RES:
			ret = 0;
			goto end;
		default:
			printf("UNKNOWN\n");
			for(i=0; i < len;i++){
			  printf("%02x ", buf[i]);
			}
			printf("\n");
			ret = -1;
			goto end;
		}
	}
end:
	return ret;
}

static int notify_device_id;
int num_driver;
int num_service;
struct service_driver **driver_ent;
struct service *service_ent;
void default_service_init(struct service *service, int s)
{
	static struct sqlite3_stmt *stmt;
	int chara_id;
	uuid_t uuid;
	printf("ID%d\n", service->service_id);
	if(stmt == NULL)
		stmt = get_stmt("SELECT chara_id,uuid FROM ble_chara WHERE service_id = $1;");
	sqlite3_bind_int(stmt, 1, service->service_id);
	while(sqlite3_step(stmt) == SQLITE_ROW){
		chara_id = sqlite3_column_int(stmt, 0);
		memcpy(&uuid, sqlite3_column_blob(stmt, 1), sizeof(uuid));
		printf("%x %x\n", chara_id, uuid.time_low);
	}
	sqlite3_reset(stmt);
	return;
}
int register_driver(struct service_driver * drv)
{
	num_driver++;
	driver_ent = realloc(driver_ent, sizeof(struct service_driver *)*
			     num_driver);
	driver_ent[num_driver -1] = drv;
	return 0;
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
	notify_device_id = device_id;
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
		ptr = sqlite3_column_blob(stmt, 1);
		if(ptr != NULL)
			memcpy(&uuid, ptr, sizeof(uuid));
		else{
			printf("Pointer is null");
		}

		service_ent = realloc(service_ent,
				      sizeof(struct service)*(num_service+1));
		service_ent[num_service].service_id = service_id;
		service_ent[num_service].driver = &default_driver;
		service_ent[num_service].sc = NULL;
		for(i=0; i < num_driver;i++){
			if(memcmp(&driver_ent[i]->uuid, &uuid, sizeof(uuid))
			   ==0){
				service_ent[num_service].driver = driver_ent[i];
			}
		}
		
		num_service++;

	}
	sqlite3_finalize(stmt);
	for(i = 0 ; i < num_service; i++){
		service_ent[i].driver->init(&service_ent[i], s);
	} 
}
int notify_handler(unsigned char *buf, int len)
{
	static sqlite3_stmt *querychara;
	int service_id, chara_id;
	int i;
	if(querychara==NULL)
		querychara = get_stmt("SELECT service_id,chara_id FROM ble_chara  JOIN ble_attribute ON ble_attribute.attribute_id = ble_chara.value_attribute_id where handle=$1 and device_id=$2;");
	sqlite3_bind_int(querychara, 1, buf[0]|(buf[1]<<8));
	sqlite3_bind_int(querychara, 2, notify_device_id);
	sqlite3_step(querychara);
	service_id = sqlite3_column_int(querychara, 0);
	chara_id = sqlite3_column_int(querychara,1);
	sqlite3_reset(querychara);
	if(service_ent == NULL)
	  return 0;
	for(i=0; service_ent[i].service_id != service_id; i++)
		;
	if(service_ent[i].driver->notify !=NULL && service_ent[i].sc != NULL)
		service_ent[i].driver->notify(service_ent[i].sc, chara_id,
					      buf, len);
	return 0;
}

int att_to_handle(int attribute_id, int *hascache)
{
	static sqlite3_stmt *handle_stmt;
	int handle;
	if(handle_stmt ==NULL)
		handle_stmt = get_stmt("SELECT handle,count(cache) from ble_attribute WHERE attribute_id=$1");
	sqlite3_bind_int(handle_stmt, 1, attribute_id);
	sqlite3_step(handle_stmt);
	handle = sqlite3_column_int(handle_stmt, 0);
	if(hascache != NULL)
		*hascache = sqlite3_column_int(handle_stmt, 1);	
	sqlite3_reset(handle_stmt);

	return handle;
}
int le_att_write(int s, int attribute_id, unsigned char *buf, size_t len,int fla)
{
	unsigned char cmd[23];
	static sqlite3_stmt *cache_read,*cache_update;
	int handle;
	int result_len,total_len;
	int write_len;
	int off;

	handle = att_to_handle(attribute_id, NULL);
	off = 0;
	cmd[0] = ATT_OP_WRITE_REQ;
	cmd[1] = handle&0xff;
	cmd[2] = (handle>>8)&0xff;
	write_len = sizeof(cmd) - 3;
	write_len = (len > (write_len))? write_len:len;

	memcpy(cmd + 3,  buf, write_len);
	le_write(s, cmd, 3 + write_len);
	le_read(s, cmd,sizeof(cmd));
	len -= write_len;
	if(len > 0){
		printf("Large WRITE NOT supported.\n");
	}
	return write_len;
}
int le_att_read(int s, int attribute_id, unsigned char *buf, size_t len,int nocache)
{
	unsigned char cmd[23];
	static sqlite3_stmt *cache_read,*cache_update;
	int handle,hascache;
	int result_len,total_len;
	
	handle = att_to_handle(attribute_id, &hascache);
	
	if(cache_update == NULL)
		cache_update = get_stmt("UPDATE ble_attribute SET cache = $1 WHERE attribute_id=$2");
	if(cache_read == NULL)
		cache_read= get_stmt("SELECT cache FROM ble_attribute WHERE attribute_id=$1;");

	fprintf(stderr, "%d %d\n", hascache, handle);
	if(!nocache && hascache){
#define MIN(a, b) (((a)<(b))? (a) :(b))
		sqlite3_bind_int(cache_read, 1, attribute_id);
		sqlite3_step(cache_read);
		result_len = sqlite3_column_bytes(cache_read, 0);
		result_len = MIN(result_len, len);
		memcpy(buf, sqlite3_column_blob(cache_read, 0),
		       MIN(result_len, len));
		sqlite3_reset(cache_read);
		return result_len;
#undef MIN		
	}
	
	cmd[0] = ATT_OP_READ_REQ;
	cmd[1] = handle&0xff;
	cmd[2] = (handle>>8)&0xff;
	le_write(s, cmd, 3);
	result_len = le_read(s, cmd, len);
	memcpy(buf, cmd+1, result_len -1);
	total_len = 0;
	while(result_len >= mtu && total_len < len){
		total_len += (result_len-1);
		cmd[0] = ATT_OP_READ_BLOB_REQ;
		cmd[1] = handle &0xff;
		cmd[2] = handle>>8 &0xff;
		cmd[3] = total_len&0xff;
		cmd[4] = (total_len >>8) &0xff;
		le_write(s, cmd, 5);
		result_len = le_read(s, cmd, sizeof(cmd));
		
		memcpy(buf+total_len, cmd+1, result_len-1);
		if(result_len < mtu)
			break;
	}
	total_len += (result_len -1); 
	if(result_len != -1){
		sqlite3_bind_blob(cache_update, 1, buf, total_len, SQLITE_TRANSIENT);
		sqlite3_bind_int(cache_update, 2, attribute_id);
		sqlite3_step(cache_update);
		sqlite3_reset(cache_update);
	}

	return total_len;
	
}

int chardesc_to_attr(int chara_id, uuid_t *descid)
{
	int attr_id;
	static sqlite3_stmt *stmt;
	if(stmt == NULL)
		stmt = get_stmt("SELECT attribute_id FROM ble_attribute , (SELECT low_attribute_id, high_attribute_id from ble_chara WHERE chara_id=$1) AS c WHERE (attribute_id BETWEEN c.low_attribute_id AND c.high_attribute_id) AND uuid = $2 ;");
	sqlite3_bind_int(stmt, 1 , chara_id);
	sqlite3_bind_blob(stmt, 2, descid, sizeof(*descid), SQLITE_TRANSIENT);
	attr_id = -1;
	if(sqlite3_step(stmt) == SQLITE_ROW){
		attr_id =sqlite3_column_int(stmt, 0);
	}
	sqlite3_reset(stmt);	
	if(attr_id == -1)
		return -1;
	return attr_id;
}

int le_char_desc_read(int s, int chara_id, uuid_t *descid, unsigned char *buf, size_t len, int nocache)
{
	int attr_id = chardesc_to_attr(chara_id, descid);
	
	return (attr_id==-1)?-1:le_att_read(s, attr_id, buf, len, nocache);
	
}
int le_char_desc_write(int s, int chara_id, uuid_t *descid, unsigned char *buf, size_t len, int flag)
{
	int attr_id = chardesc_to_attr(chara_id, descid);
	
	return (attr_id==-1)?-1:le_att_write(s, attr_id, buf, len, flag);
	
}

int char_to_attr(int chara_id)
{
  	int attr_id = -1;
	static sqlite3_stmt *stmt;
	if(stmt == NULL)
		stmt = get_stmt("SELECT value_attribute_id FROM ble_chara where chara_id = $1;");
	sqlite3_bind_int(stmt, 1, chara_id);
	
	if(sqlite3_step(stmt) == SQLITE_ROW){
		attr_id =sqlite3_column_int(stmt, 0);
	}
	sqlite3_reset(stmt);
	return attr_id;
}
int le_char_read(int s, int chara_id, unsigned char *buf, size_t len, int nocache)
{
	int attr_id = char_to_attr(chara_id);
	
	return (attr_id==-1)? -1: le_att_read(s, attr_id, buf, len, nocache);	
}


void probe_service(int s, int device_id)
{
	sqlite3_stmt *iter_serv, *update_serv;
	int service_id, request_id;
	uuid_t srvuuid;
	int len;
	unsigned char buf[40];
	
	iter_serv = get_stmt("SELECT service_id,low_attribute_id FROM ble_service where device_id =$1;");
	update_serv = get_stmt("UPDATE ble_service SET uuid = $1 WHERE service_id = $2;");
	sqlite3_bind_int(iter_serv, 1, device_id);
	while(sqlite3_step(iter_serv)==SQLITE_ROW){
		service_id = sqlite3_column_int(iter_serv, 0);
		request_id = sqlite3_column_int(iter_serv, 1);
		len = le_att_read(s,request_id, buf, sizeof(buf), 0);
		if(len == 2){
			srvuuid = uuid_base;
			srvuuid.time_low = buf[0]|(buf[1]<<8);
		}else{
			memcpy(&srvuuid, buf, sizeof(srvuuid));
		}
		sqlite3_bind_blob(update_serv, 1, &srvuuid, sizeof(srvuuid), SQLITE_TRANSIENT);
		sqlite3_bind_int(update_serv, 2, service_id);
		sqlite3_step(update_serv);
		sqlite3_reset(update_serv);
	}
	sqlite3_finalize(update_serv);
	sqlite3_finalize(iter_serv);


}
void probe_chara(int s, int device_id)
{
	sqlite3_stmt *iter_chara, *update_chara;
	int chara_id, attribute_id, chandle;
	unsigned char buf[40];
	uuid_t srvuuid;
	int len;
	int prop;
	iter_chara = get_stmt("SELECT chara_id,low_attribute_id FROM ble_chara INNER JOIN ble_attribute on low_attribute_id=ble_attribute.attribute_id  where device_id =$1;");
	update_chara = get_stmt("UPDATE ble_chara SET uuid = $1, property = $2, value_attribute_id = (SELECT attribute_id FROM ble_attribute where handle = $3 and device_id = $4 ) WHERE chara_id = $5;");
	sqlite3_bind_int(iter_chara, 1, device_id);
	printf("%p %p\n", iter_chara, update_chara);
	while(sqlite3_step(iter_chara)==SQLITE_ROW){
		chara_id = sqlite3_column_int(iter_chara, 0);
		attribute_id = sqlite3_column_int(iter_chara, 1);
		printf("%d %d\n", chara_id, attribute_id);
		len = le_att_read(s,attribute_id, buf, sizeof(buf), 0);
		prop = buf[0];
		chandle = buf[1]|buf[2]<<8;
		if(len == 5){
			srvuuid = uuid_base;
			srvuuid.time_low = buf[3]|(buf[4]<<8);
		}else{
			memcpy(&srvuuid, buf+3, sizeof(srvuuid));
		}
		sqlite3_bind_blob(update_chara, 1, &srvuuid, sizeof(srvuuid), SQLITE_TRANSIENT);
		sqlite3_bind_int(update_chara, 2, prop);
		sqlite3_bind_int(update_chara, 3, chandle);
		sqlite3_bind_int(update_chara, 4, device_id);
		sqlite3_bind_int(update_chara, 5, chara_id);
		sqlite3_step(update_chara);
		sqlite3_reset(update_chara);
	}
	sqlite3_finalize(update_chara);
	sqlite3_finalize(iter_chara);


}

int le_l2connect(bdaddr_t *bd, int securecon)
{
	struct sockaddr_l2cap l2c;
	int s;
	unsigned char buf[40];
	ssize_t len;
	int i;
	uint16_t buid,handle = 1;
	uint16_t conhandle = 0;
	int count;
	uint16_t enc;
	int device_id;
	
	s = socket(PF_BLUETOOTH, SOCK_SEQPACKET,
		   BLUETOOTH_PROTO_L2CAP);  
	l2c.l2cap_len = sizeof(l2c);
	l2c.l2cap_family = AF_BLUETOOTH;
	l2c.l2cap_psm = 0;
	l2c.l2cap_cid = NG_L2CAP_ATT_CID;
	l2c.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	bcopy(bd, &l2c.l2cap_bdaddr, sizeof(*bd));
	
	printf("CONNECT\n");
	enc = 1;

	if(securecon){
		if(setsockopt(s, SOL_L2CAP, SO_L2CAP_ENCRYPTED, &enc, sizeof(enc))<0){
			err(2, "SETSOCKOPT FAILED");
		}
	}

	if(connect(s, (struct sockaddr *) &l2c, sizeof(l2c))!= 0){
		perror("connect");
	}
	printf("CONNECTOK\n");	

	buf[0]=ATT_OP_MTU_REQ;
	buf[1]=mtu&0xff;
	buf[2]=mtu>>8;
	le_write(s,buf,3);
	le_read(s,buf,sizeof(buf));
	printf("MTU %d\n", mtu);
	device_id = search_device(l2c.l2cap_bdaddr_type, l2c.l2cap_bdaddr);
	if(device_id != 0){
		printf("ATTRIBUTE %d\n",device_id);
		goto skip;
	}
	device_id = create_device(l2c.l2cap_bdaddr_type, l2c.l2cap_bdaddr);
	
	for(;;){
		buf[0] = ATT_OP_FIND_INFO_REQ;
		buf[1] = handle &0xff;
		buf[2] = handle >>8;
		buf[3] = 0xff;
		buf[4] = 0xff;
		le_write(s,buf,5);
		if((len = le_read(s, buf,sizeof(buf)))<0){
			break;
		}
		if(buf[1] == 1){
			for(i=2; i < len;i+= 4){
				uint32_t ustat;
				char *uuidstr;
				uuid_t huuid;
				handle = buf[i+1]<<8|buf[i];
				buid = buf[i+3]<<8|buf[i+2];
				huuid = uuid_base;
				huuid.time_low = buid;
				create_attribute(device_id, handle, &huuid);
				num_handle++;	  
			}
		}else if(buf[1] == 2){
			uuid_t uuid;
			char *uuidstr;
			uint32_t status;
			uuid_dec_le( buf+4, &uuid);
			uuid_to_string(&uuid, &uuidstr, &status);
			num_handle++;	  
			create_attribute(device_id, handle, &uuid);
		}
		handle++;
	}
	end_attribute_probe(device_id);
	probe_service(s, device_id);
	probe_chara(s, device_id);
skip:	
	attach_service(s, device_id);
	while(1){
		unsigned char buf[50];
		
		le_read(s, buf, sizeof(buf));
	}
	  
	return 0;
}
int main(int argc, char *argv[])
{

	ng_hci_le_set_event_mask_cp lemc;
	char buf[NG_HCI_ADVERTISING_DATA_SIZE];
	char hname[NG_HCI_ADVERTISING_DATA_SIZE-10];
	int s;
	int ch;
	char *node="ubt0hci";
	int len,addr_valid = 0;
	bdaddr_t bd;
	int sflag = 0;
	int res = -1,handle = -1;
	uint32_t status;
	
	while((ch = getopt(argc, argv, "s") )!= -1){
		switch(ch){
		case 's':
			sflag = 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [-s] bdaddr\n", argv[0]);
			exit(-1);
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if(argc>0){
	  addr_valid = bt_aton(argv[0],&bd);
	}
	open_db("hoge.db");
	init_schema();

	//gap_probe_init(NULL);
	uuid_from_string("00000000-0000-1000-8000-00805F9B34FB", &uuid_base, &status);
	install_service_name_table();
	hogp_register();
	gethostname(hname, sizeof(hname));
	len = strlen(hname);
	if(addr_valid){
		le_l2connect(&bd, sflag);
	}
	
	return 0;
}
	
