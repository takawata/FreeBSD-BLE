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

extern uuid_t uuid_base;
struct midi_service{
	int timestamp;
	int insysex;
	char sysexbuf[50];
};
void midi_init(struct service *service, int s);
void midi_notify(void *sc, int charid, unsigned char *buf, size_t len);

static struct service_driver midi_driver __attribute__((used)) __attribute__((section(("driver"))))=
{
	.uuid = {0x03B80E5A,0xEDE8,0x4B33,0xA7,0x51,{0x6C,0xE3,0x4E,0xC4,0xC7,0x00}},
	.init = midi_init,
	.notify = midi_notify
};
 
void midi_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	int i ,j;
       
	struct midi_service *ms = sc;
	
	printf("MIDI Notify: LEN%zu\n", len);
	int timestamp, header;
	int channel;
	
	if(!(buf[2]&0x80)){
	  printf("Invalid Header Format\n");
	}
	header = buf[2]&0x5f;
	i = 3;

	if(ms->insysex){
		for(; i < len - 1; i++){
			if(buf[i]&0x80)
				break;
			ms->insysex++;
			if(ms->insysex < sizeof(ms->sysexbuf)){
				ms->sysexbuf[ms->insysex] = buf[i];
			}
		}
	}
	
	while(i < len - 1){
		timestamp = header << 7;		
		if(!(buf[i]&0x80)){
			printf("Invalid timestamp Format\n");
			//return;
		}
		timestamp |= buf[i]&0x7f;
		i++;
		if( (buf[i]&0x80)&& (buf[i] != 0xf0)){
			ms->insysex = 0;
		}
		printf("Time %d",  timestamp);		
		//SysEx
		if(buf[i]==0xf0){
			for(; i < len; i++){
				printf("SYSEX START");
				if(buf[i]&0x80)
					break;
				ms->sysexbuf[ms->insysex] = buf[i];
				ms->insysex++;
 			}
			continue;
		}
		//SysEx End
		if(buf[i] == 0xf7){
			printf("Sysex END");
			for(j=0;j< ms->insysex; j++){
				printf("%x\n", ms->sysexbuf[j]);
			}
			ms->insysex = 0;
		}
		
		channel = buf[i]&0xf;
		printf("Channel %d", channel);
		switch(buf[i]&0xf0){
		case 0x80:
			printf("Note OFF");
			break;
		case 0x90:
			printf("Note ON");
			break;
		case 0xa0:
			printf("Polyphonic Key");
			break;
		case 0xb0:
			printf("CTRL Change" );
			break;
		case 0xc0:
			printf("After Touch");
			break;
		case 0xd0:
			printf("Channel Pressure");
			break;
		case 0xe0:
			printf("Pitch vend");
			break;
		case 0xf0:
			printf("Special\n");
			break;
		}
		printf("%d %d\n", buf[i+1], buf[i+2]);
		i += 3;
	}
		
		

	
	for(i=2; i < len ;i ++){
		printf("%02x ", buf[i]);
	}
	printf("\n");
}
void midi_init(struct service *service, int s)
{
	unsigned char buf[40];
	uuid_t uuid;
	int len;
	int error;
	struct midi_service *serv;
	int cid;
	sqlite3_stmt *stmt;
	uuid_t midi_chara = {0x7772E5DB, 0x3868, 0x4112,0xA1,0xA9,{0xF2,0x66,0x9D,0x10,0x6B,0xF3}};
	serv = malloc(sizeof(*serv));
	service->sc = serv;
	serv->timestamp = 0;
	serv->insysex = 0;
	
	cid = get_cid_by_uuid(service, &midi_chara);
	if(cid != -1){
		register_notify(cid, service, s);
	}else{
		printf("Watch Chara not found\n");
	}
	
	return ;
}
