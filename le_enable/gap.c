#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <usbhid.h>
#include "att.h"
#include "gap.h"
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
char *uuidtoservice(uint16_t uuid)
{
	struct serviceent *s;
	static char unknown[]="XXXXX";
	for(s = srvent; s->name != NULL; s++){
		if(uuid == s->uuid)
			return s->name;
	}
	snprintf(unknown, sizeof(unknown), "%x", uuid);
	return unknown;
}
int gap_probe(int s, struct handle_entry *hent, int num_handle )
{
	unsigned char buf[40];
  	int i,j;
	int len;
	uint16_t uuid16, handle;
	for(i = 0; i < num_handle; i++){
		if(hent[i].uuid16== 0x2800||
		   hent[i].uuid16== 0x2801||
		   hent[i].uuid16== 0x2803)
		{
			hent[i].permission = GATT_PERM_READ;
		}
		printf("HANDLE %x Permission: %x\n",hent[i].handle,
		       hent[i].permission);
		buf[0] = ATT_OP_READ_REQ;
		buf[1] = hent[i].handle&0xff;
		buf[2] = (hent[i].handle>>8)&0xff;
		le_att_write(s, buf,3);
		len = le_att_read(s,buf,sizeof(buf));
		switch(hent[i].uuid16){
		case 0x2800:
			uuid16 = buf[1]|buf[2]<<8;
			printf("primary service %s\n", uuidtoservice(uuid16));
			break;
		case 0x2801:
			uuid16 = buf[1]|buf[2]<<8;			
			printf("secondary service %s\n",
			       uuidtoservice(uuid16));
			break;
		case 0x2802:
			printf("include handle %x-%x uuid %x\n",
			       buf[1]|buf[2]<<8, buf[3]|buf[4]<<8,
			       buf[5]|buf[6]<<8);
			break;
		case 0x2803:
			uuid16 = buf[4]|buf[5]<<8;
			handle = buf[2]|buf[3]<<8;			
			printf("permission %x handle %x char %x\n",
			       buf[1], handle, uuid16);
			for(j=i+1; j < num_handle; j++){
				if(hent[j].handle == handle){
					if(hent[j].uuid16 == uuid16){
						hent[j].permission = buf[1];
					}else{
						printf("Handle and UUID not match\n");
					}
				}
			}
			break;
		case 0x2a00:
			buf[len] = 0;
			printf("Device Name: %s\n", buf+1);
			break;
		case 0x2a19:
			printf("Battery Remaining: %d%%\n", *(buf+1));
			break;
		case 0x2a26:
			buf[len] = 0;
			printf("Firmware Revision: %s\n", buf+1);
			break;
		case 0x2a28:
			buf[len] = 0;
			printf("Software Revision: %s\n", buf+1);
			break;

		case 0x2a29:
			buf[len] = 0;
			printf("Manifacturare name: %s\n", buf+1);
			break;
		case 0x2a4b:
		{
			report_desc_t rd;
			hid_data_t hd;
			hid_item_t it;
			int res;
			int off;
			unsigned char hidbuf[512];
			memset(hidbuf, 0, sizeof(hidbuf));
			off = 0;
			do{
			  memcpy(hidbuf+off, buf+1, len-1);
			  off += (len-1);
			  buf[0] = ATT_OP_READ_BLOB_REQ;
			  buf[1] = hent[i].handle &0xff;
			  buf[2] = hent[i].handle>>8 &0xff;
			  buf[3] = off&0xff;
			  buf[4] = (off >>8) &0xff;
			  le_att_write(s, buf, 5);
			  len = le_att_read(s, buf, sizeof(buf));
			  if(len == -1)
			    break;
			}while(len >= 23);
			memcpy(hidbuf+off, buf+1, len-1);	
			off += (len-1);
			printf("%02x  %d %d\n", buf[1], len, off);
			for(i=0; i < off; i++){
			  printf("%02x ", hidbuf[i]);
			}
			rd = hid_use_report_desc(hidbuf, off);
			hd = hid_start_parse(rd, ~0, -1);
			while((res = hid_get_item(hd, &it)) > 0){
				printf("res %d\n", res);
				printf("up%x lmin%d lmax%d pmin%x  pmax%x ",
				       it._usage_page,
				       it.logical_minimum,
				       it.logical_maximum,
				       it.physical_minimum,
				       it.physical_maximum);
				printf("ue%x u%x rsz%x  rid%x rcnt%x ",
				       it.unit_exponent,
				       it.unit,
				       it.report_ID,
				       it.report_count,
				       it.usage);
				printf("us%d umin%d umax%d di%d dmin%d dmax%d ",
				       it.usage,
				       it.usage_minimum,
				       it.usage_maximum,
				       it.designator_index,
				       it.designator_minimum,
				       it.designator_maximum);
				printf("si%d smin%d smax%d sd%d col%d cvel%d ",
				       it.string_index,
				       it.string_minimum,
				       it.string_maximum,
				       it.set_delimiter,
				       it.collection,
				       it.collevel);
				printf("ki %d fl %d pos %d\n",
				       it.kind, it.flags, it.pos);
				
			}
			hid_dispose_report_desc(rd);
			break;
		}
		default:
			printf("characteristic: %x\n", hent[i].uuid16);
			break;
		}
	}
	
	return 0;
}
