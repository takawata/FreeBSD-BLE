
struct eventhandler{
	int (*handler)(int s, int kqflag, void *data);
	void *data;
};

int init_event();
int register_event(int s, struct eventhandler *evh);
int event_handler();

