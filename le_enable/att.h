#define ATT_OP_ERR 1
#define ATT_OP_MTU_REQ 2
#define ATT_OP_MTU_RES 3
#define ATT_OP_FIND_INFO_REQ 4
#define ATT_OP_FIND_INFO_RES 5
#define ATT_OP_FIND_TYPE_REQ 6
#define ATT_OP_FIND_TYPE_RES 7
#define ATT_OP_READ_TYPE_REQ 8
#define ATT_OP_READ_TYPE_RES 9
#define ATT_OP_READ_REQ 0xa
#define ATT_OP_READ_RES 0xb
#define ATT_OP_READ_BLOB_REQ 0xc
#define ATT_OP_READ_BLOB_RES 0xd
#define ATT_OP_READ_MULT_REQ 0xe
#define ATT_OP_READ_MULT_RES 0xf
#define ATT_OP_READ_GROUP_REQ 0x10
#define ATT_OP_READ_GROUP_RES 0x11
#define ATT_OP_WRITE_REQ 0x12
#define ATT_OP_WRITE_RES 0x13
#define ATT_OP_WRITE_COMMAND 0x52
#define ATT_OP_WRITE_SIGNED 0xd2
#define ATT_OP_WRITE_PRE_REQ 0x16
#define ATT_OP_WRITE_PRE_RES 0x17
#define ATT_OP_EXECUTE_WRITE 0x18
#define ATT_OP_NOTIFY 0x1b
#define ATT_OP_INDICATE 0x1d
#define ATT_OP_CONFIRM 0x1e

int le_att_write(int s,unsigned char *buf,size_t size);
int le_att_read(int s, unsigned char *buf, size_t size);
