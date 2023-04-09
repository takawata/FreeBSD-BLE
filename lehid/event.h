
struct eventhandler{
	int (*handler)(int s, int kqflag, void *data);
	void *data;
};

int init_event();
int register_event(int s, struct eventhandler *evh);
int deregister_event(int s);
int event_handler();

