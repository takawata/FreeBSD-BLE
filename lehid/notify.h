#ifndef NOTIFY_H_
#define NOTIFY_H_
int register_notify(int cid, struct service *serv, int s);
int notify_handler(unsigned char *buf, int len);
#endif
