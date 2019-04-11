#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include "event.h"

static int numevent;
static int kqdesc;

int init_event()
{
	kqdesc = kqueue();
	if(kqdesc == -1)
		return -1;
	return 0;
}
/*
 * Register event . event handler should not be transient.
 */
int register_event(int s, struct eventhandler *evh)
{
	struct kevent ke;
	EV_SET(&ke, s, EVFILT_READ, EV_ADD , 0, 0, evh);
	if(kevent(kqdesc, &ke, 1, NULL, 0, NULL)==-1){
		perror("kevent");
	}
	return 0;
}
int deregister_event(int s)
{
	struct kevent ke;
	EV_SET(&ke, s, EVFILT_READ, EV_DELETE, 0, 0, 0);
	if(kevent(kqdesc, &ke, 1, NULL, 0, NULL)==-1){
		perror("kevent");
	}
	return 0;
}
int event_handler()
{
	struct eventhandler *evh;
	struct kevent ke;
	int nevent;
	for(;;){
		nevent = kevent(kqdesc, NULL, 0, &ke, 1, NULL);
		if(nevent){
			evh=ke.udata;
			evh->handler(ke.ident, ke.flags, evh->data);
		}
	}
	return 0;
}
