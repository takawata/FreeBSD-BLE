#ifndef SERVICE_H_
#define SERVICE_H_
struct service;
struct service_driver;
typedef void (*init_func)(struct service *, int sock);
typedef void (*notify_func)(void *softc, int chara_id, unsigned char *buf, size_t len);
struct service_driver{
	uuid_t uuid;
	init_func init;
	notify_func notify;
};
struct service{
	int service_id;
	void *sc;
	struct service_driver *driver;
};

int attach_service(int s, int device_id );

#endif
