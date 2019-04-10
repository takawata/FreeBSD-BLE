#ifndef SERVICE_H_
#define SERVICE_H_
struct service;
struct service_driver;
/*
 *Initialize function type. sock is socket descriptor to access peripheral
 */
typedef void (*init_func)(struct service *, int sock);
/*
 *Notify or Indicate funtion. softc is per service structure. 
 *chara_id is from database table. buf is raw BLE packet. len is the packet len.
 */
typedef void (*notify_func)(void *softc, int chara_id, unsigned char *buf, size_t len);
/*
 * Service driver structure. 
 * This structure should be statically defined and put "driver" ELF section.
 * This structure is implicitly used so __attribute__((used)) should be 
 * exist to prevent optimization from compiler.
 */
struct service_driver{
	uuid_t uuid;
	init_func init;
	notify_func notify;
};
/*
 * service structure. this structure allocated per service detected.
 * It is up to service driver to initialize sc (software context) member.
 */
struct service{
	int service_id;
	void *sc;
	struct service_driver *driver;
};

int attach_service(int s, int device_id );

#endif
