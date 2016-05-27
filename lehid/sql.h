#ifndef SQL_H_
#define SQL_H_
void init_schema();
int create_attribute(int device_id, int handle, uuid_t *uuid);
int search_device(int addrtype, bdaddr_t addr);
int create_device( int addrtype, bdaddr_t addr);
int start_attribute_probe(int);
int end_attribute_probe(int);
int open_db(char *);
sqlite3_stmt *get_stmt(char*);
#endif
