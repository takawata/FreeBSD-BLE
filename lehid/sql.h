#ifndef SQL_H_
#define SQL_H_
void init_schema();
int create_attribute(int device_id, int handle, uuid_t *uuid);
int search_device(int addrtype, bdaddr_t addr);
int create_device( int addrtype, bdaddr_t addr);
int start_attribute_probe(int);
int end_attribute_probe(int);
void create_uuid_func();
int open_db(char *);
sqlite3_stmt *get_stmt(char*);
int my_bind_uuid(sqlite3_stmt *stmt, int col, uuid_t *uuid);
int my_column_uuid(sqlite3_stmt *stmt, int col, uuid_t *uuid);
#endif
