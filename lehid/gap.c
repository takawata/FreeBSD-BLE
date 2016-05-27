#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <usbhid.h>
#include <string.h>
#include <dev/usb/usbhid.h>
#include <uuid.h>
#include "att.h"
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
struct gatt_service{
	uuid_t uuid;
	struct handle_entry *begin;
	struct handle_entry *end;
//	SLIST_ENTRY(att_service) next;
};

int gap_probe_init(char *tbl)
{
	hid_init(tbl);
	return 0;
}
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


//SLIST_HEAD(services, gatt_service);
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
		   hent[i].uuid16== 0x2802||
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
		{
			uuid_t uuid;
			char *uuidstr;
			uint32_t status;
			if(len == 6){
				uuid = uuid_base;
				uuid.time_low = buf[4]|buf[5]<<8;
			}else{
				uuid_dec_le(buf+4, &uuid);
			}
			handle = buf[2]|buf[3]<<8;
			uuid_to_string(&uuid, &uuidstr,&status);
			printf("permission %x handle %x char %s\n",
			       buf[1], handle, uuidstr);
			free(uuidstr);
			for(j=i+1; j < num_handle; j++){
				if(hent[j].handle == handle){
					if(uuid_equal(&uuid, &hent[j].uuid,&status)){
						hent[j].permission = buf[1];
					}else{
						uuid_to_string(&hent[j].uuid, &uuidstr, &status);
						printf("Handle and UUID not match !%s\n", uuidstr);
						free(uuidstr);
					}
				}
			}
			break;
		}
		case 0x2a00:
			buf[len] = 0;
			printf("Device Name: %s\n", buf+1);
			break;
		case 0x2a19:
			printf("Battery Remaining: %d%%\n", *(buf+1));
			break;
		case 0x2a24:
			buf[len] = 0;
			printf("Model Number: %s\n", buf+1);
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
		case 0x2907:
			printf("External Report Ref: %04x\n", buf[1]|(buf[2]<<8));
			break;
		case 0x2908:
			printf("Report ID: %d Report map %s\n",
			       buf[1], (buf[2] ==1)?"Input":(buf[2]==2)?
			       "Output":(buf[2]==3)?"Feature":"???");
			break;
			
		case 0x2a4b:
		{
			report_desc_t rd;
			hid_data_t hd;
			hid_item_t it;
			int res;
			int off;
			unsigned char hidbuf[MAX_ATTRIBUTE_LEN];
			memset(hidbuf, 0, sizeof(hidbuf));
			off = 0;
			memcpy(hidbuf, buf+1, len-1);
			while(len >= 23){
				off += (len-1);
				printf("off: %d %d\n", off, len);		
				buf[0] = ATT_OP_READ_BLOB_REQ;
				buf[1] = hent[i].handle &0xff;
				buf[2] = hent[i].handle>>8 &0xff;
				buf[3] = off&0xff;
				buf[4] = (off >>8) &0xff;
				le_att_write(s, buf, 5);
				len = le_att_read(s, buf, sizeof(buf));
				if(len == -1)
					break;
				memcpy(hidbuf+off, buf+1, len-1);
			}
			off += (len-1);
			printf("%02x  %d %d\n", buf[1], len, off);
			for(j=0; j < off; j++){
			  printf("%02x ", hidbuf[j]);
			}
			printf("\n");			
			rd = hid_use_report_desc(hidbuf, off);
			hd = hid_start_parse(rd, ~0, -1);
			for (hd = hid_start_parse(rd, ~0, -1); hid_get_item(hd, &it); ) {			
#if 1
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
#endif			  
			}

			hid_dispose_report_desc(rd);
			break;
		}
		default:
		{
			int j;
			printf("DEF%d\n", len);
			for(j=1; j < len; j++){
				printf("%02x ", buf[j]);
			}
			printf("\n");
			break;
		}
		}
		printf("\n");
	}

	return 0;
}
