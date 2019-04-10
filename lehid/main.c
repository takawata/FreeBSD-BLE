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
#include "gatt.h"
#include "uuidbt.h"
#include <sqlite3.h>
#include <getopt.h>
#include <sys/event.h>
#include "sql.h"
#include "service.h"
#include "att.h"
#include "event.h"

//00000000-0000-1000-8000-00805F9B34FB

uuid_t uuid_base = UUID16(0);

int timeout = 30;


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
		btuuiddec(buf, len, &srvuuid);
		my_bind_uuid(update_serv, 1, &srvuuid);
		sqlite3_bind_int(update_serv, 2, service_id);
		sqlite3_step(update_serv);
		sqlite3_reset(update_serv);
	}
	sqlite3_finalize(update_serv);
	sqlite3_finalize(iter_serv);


}
void probe_include(int s, int device_id)
{
	sqlite3_stmt *iter_include, *update_include;
	int include_id, attribute_id, lhandle,hhandle;
	unsigned char buf[40];
	uuid_t srvuuid;
	int len;
	int prop;
	printf("PROBE_INCLUDE\n");
	iter_include = get_stmt("SELECT include_id,def_attribute_id FROM ble_include INNER JOIN ble_attribute on def_attribute_id=ble_attribute.attribute_id  where device_id =$1;");
	update_include = get_stmt("UPDATE ble_include SET low_attribute_id = (SELECT attribute_id FROM ble_attribute where handle = $1 and device_id = $2 ), high_attribute_id= (SELECT attribute_id FROM ble_attribute where handle = $3 and device_id = $2 ) WHERE include_id = $4;");
	sqlite3_bind_int(iter_include, 1, device_id);
	printf("%p %p\n", iter_include, update_include);
	while(sqlite3_step(iter_include)==SQLITE_ROW){
		include_id = sqlite3_column_int(iter_include, 0);
		attribute_id = sqlite3_column_int(iter_include, 1);
		printf("%d %d\n", include_id, attribute_id);
		len = le_att_read(s,attribute_id, buf, sizeof(buf), 0);
		lhandle = buf[0]|buf[1]<<8;
		hhandle = buf[2]|buf[3]<<8;		
		sqlite3_bind_int(update_include, 1, lhandle);
		sqlite3_bind_int(update_include, 2, device_id);
		sqlite3_bind_int(update_include, 3, hhandle);
		sqlite3_bind_int(update_include, 4, include_id);		
		sqlite3_step(update_include);
		sqlite3_reset(update_include);
	}
	sqlite3_finalize(update_include);
	sqlite3_finalize(iter_include);

	
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
		btuuiddec(buf+3, len-3, &srvuuid);
		my_bind_uuid(update_chara, 1, &srvuuid);
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
int attribute_init(int s, int device_id)
{
	unsigned char buf[40];
	ssize_t len;
	int i;
	uint16_t buid,handle = 1;
	uint16_t conhandle = 0;
	int count;
	
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
				btuuid16(buid, &huuid);
				create_attribute(device_id, handle, &huuid);
			}
		}else if(buf[1] == 2){
			uuid_t uuid;
			char *uuidstr;
			uint32_t status;
			uuid_dec_bt( buf+4, &uuid);
			create_attribute(device_id, handle, &uuid);
		}
		handle++;
	}
	end_attribute_probe(device_id);

	return 0;
}

/*
 * STDIN input event.
 */
int cmdhandler(int c, int kqflag, void * data)
{
	unsigned char buf[50];
	int len;
	printf("%d\n", kqflag);
	if(kqflag == EV_EOF){

		deregister_event(c);
	}
	len =  read(0, buf, sizeof(buf) -1);
	printf("%d\n",len);
	if(len <= 0){

		deregister_event(c);		
	}
	buf[len] = 0;
	//process_command(buf);
	
	return 0;
}

/* 
 *LE packet incoming event.
 */
int le_event(int s, int kqflag, void *data)
{
	unsigned char buf[50];
	if(kqflag == EV_EOF){
		printf("EOF GET\n");
		exit(-1);
	}
	le_read_one(s, buf,sizeof(buf));

	return 0;
}

int le_l2connect(bdaddr_t *bd, int securecon, int israndom)
{
	struct sockaddr_l2cap l2c;
	int s;
	uint16_t enc;
	int device_id;
	static struct  eventhandler evh, cmd;
	s = socket(PF_BLUETOOTH, SOCK_SEQPACKET,
		   BLUETOOTH_PROTO_L2CAP);  
	l2c.l2cap_len = sizeof(l2c);
	l2c.l2cap_family = AF_BLUETOOTH;
	l2c.l2cap_psm = 0;
	l2c.l2cap_cid = NG_L2CAP_ATT_CID;
	l2c.l2cap_bdaddr_type = (israndom)? BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
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
#if 0
	buf[0]=ATT_OP_MTU_REQ;
	buf[1]=mtu&0xff;
	buf[2]=mtu>>8;
	le_write(s,buf,3);
	le_read(s,buf,sizeof(buf));
	printf("MTU %d\n", mtu);
#endif	
	device_id = search_device(l2c.l2cap_bdaddr_type, l2c.l2cap_bdaddr);
	if(device_id != 0){
		goto skip;
	}
	device_id = create_device(l2c.l2cap_bdaddr_type, l2c.l2cap_bdaddr);

	attribute_init(s, device_id);
	probe_service(s, device_id);
	probe_chara(s, device_id);
	probe_include(s, device_id);
skip:
	attach_service(s, device_id);
	evh.handler = le_event;
	evh.data = NULL;
	register_event(s, &evh);
	cmd.handler = cmdhandler;
	cmd.data = NULL;
	register_event(0, &cmd);
	event_handler();

	return 0;
}
int main(int argc, char *argv[])
{

	ng_hci_le_set_event_mask_cp lemc;
	int s;
	int ch;
	char *node="ubt0hci";
	int len,addr_valid = 0;
	bdaddr_t bd;
	int sflag = 0,rflag = 0;
	int res = -1,handle = -1;
	uint32_t status;
	
	while((ch = getopt(argc, argv, "rs") )!= -1){
		switch(ch){
		case 's':
			sflag = 1;
			break;
		case 'r':
			rflag = 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [-r] [-s] bdaddr\n", argv[0]);
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
	create_uuid_func();
	//gap_probe_init(NULL);
	//uuid_from_string("00000000-0000-1000-8000-00805F9B34FB", &uuid_base, &status);
	//install_service_name_table();
	init_event();	
	if(addr_valid){
		le_l2connect(&bd, sflag, rflag);
	}

	return 0;
}
	
