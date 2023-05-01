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
#include "notify.h"

static int mtu = 23;
int num_handle = 0;
static unsigned char sentcmd[12];
int le_write(int s, unsigned char *buf, size_t siz)
{
	memcpy(sentcmd, buf, sizeof(sentcmd));
	return write(s, buf, siz);
}

/*
 * Process LE packet from peripheral.
 * Return value
 * >=0 len.
 * -1 error
 * -2 not response.
 */
int le_read_one(int s,unsigned char *buf,size_t buflen)
{
	int i;
	int len;
	int ret = 0;
	uint16_t handle,chandle;
	
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
		break;
	case ATT_OP_READ_RES:
		for(i=1; i < len;i++){
			printf("%02x ", buf[i]);
		}
		printf("\n");
		if(sentcmd[0] != ATT_OP_READ_REQ){
			printf("SPRIOUS READ\n");
			ret = -1;
		}		  
		break;
	case ATT_OP_FIND_INFO_RES:
		if(sentcmd[0] != ATT_OP_FIND_INFO_REQ){
			printf("SPRIOUS FINDRES\n");
			ret = -1;
		}
		break;
	case ATT_OP_MTU_RES:
		if(sentcmd[0] != ATT_OP_MTU_REQ){
			printf("SPRIOUS MTU\n");
			ret = -1;
		}
		mtu = buf[1]|(buf[2]<<8);
		break;
	case ATT_OP_READ_BLOB_RES:
		if(sentcmd[0] != ATT_OP_READ_BLOB_REQ){
			printf("SPRIOUS BLOBRES\n");
			ret = -1;
		}
		break;
	case ATT_OP_NOTIFY:
		notify_handler(buf+1, len - 1, 0, s);
		ret = -2;
		break;
	case ATT_OP_INDICATE:
		notify_handler(buf+1, len - 1, 1, s);
		ret = -2;
		break;
		
	case ATT_OP_FIND_INFO_REQ:
		printf("FIND_INFO\n");
		ret = -2;
		break;
	case ATT_OP_FIND_TYPE_REQ:
		printf("FIND_TYPE\n");
		for(i=1; i < len;i++){
			printf("%02x ", buf[i]);
		}
		printf("\n");
		ret = -2;
		break;
	case ATT_OP_WRITE_RES:
		ret = 0;
		break;
	default:
		printf("UNKNOWN\n");
		for(i=0; i < len;i++){
			printf("%02x ", buf[i]);
		}
		printf("\n");
		ret = -1;
		break;
	}
	return ret;
}

/*
 * Wait for data response from peripheral.
 */
int le_read(int s,unsigned char *buf,size_t buflen)
{
	int ret;
	/*
	 * if peer initiated request received, 
	 * Wait for data again.
	 */
	while((ret = le_read_one(s,buf,buflen)) == -2)
		;

	return ret;
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

int get_cid_by_uuid(struct service *service, uuid_t *uuid)
{
	static sqlite3_stmt *stmt;
	int cid;
	int error ;
	
	if(stmt == NULL)
		stmt = get_stmt("SELECT chara_id from ble_chara where service_id = $1 and uuid = $2;");

	sqlite3_bind_int(stmt, 1, service->service_id);
	my_bind_uuid(stmt, 2, uuid);
	
	if((error = sqlite3_step(stmt)) != SQLITE_ROW){
		//printf("%x NOT FOUND\n", uuid16);
		cid = -1;
		goto end;
	
	}
	cid = sqlite3_column_int(stmt, 0);
 end:	
	sqlite3_reset(stmt);
	return cid;
}

int get_cid_by_uuid16(struct service *service, int uuid16)
{
	static sqlite3_stmt *stmt;
	uuid_t uuid;
	int cid;
	int error ;
	btuuid16(uuid16, &uuid);
	return get_cid_by_uuid(service, &uuid);
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
	if(result_len == -1){
	  total_len = result_len;

	  goto end;
	}
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
 end:
	return total_len;
	
}

int chardesc_to_attr(int chara_id, uuid_t *descid)
{
	int attr_id;
	static sqlite3_stmt *stmt;
	if(stmt == NULL)
		stmt = get_stmt("SELECT attribute_id FROM ble_attribute , (SELECT low_attribute_id, high_attribute_id from ble_chara WHERE chara_id=$1) AS c WHERE (attribute_id BETWEEN c.low_attribute_id AND c.high_attribute_id) AND uuid = $2 ;");
	sqlite3_bind_int(stmt, 1 , chara_id);
	my_bind_uuid(stmt, 2, descid);
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

int le_char_write(int s, int chara_id, unsigned char *buf, size_t len, int flag)
{
	int attr_id = char_to_attr(chara_id);
	
	return (attr_id==-1)? -1: le_att_write(s, attr_id, buf, len, flag);	
}


