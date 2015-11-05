struct handle_entry{
	uint16_t handle;
	uint16_t uuid16;
	uint16_t permission;
	int value;
};
#define GATT_PERM_BROADCAST 1
#define GATT_PERM_READ 2
#define GATT_PERM_WRITE_NR 4
#define GATT_PERM_WRITE 8
#define GATT_PERM_NOTIFY 0x10
#define GATT_PERM_INDICATE 0x20
#define GATT_PERM_WRITE_S 0x40
#define GATT_PERM_EXT 0x80

static struct handle_entry *hent;
int gap_probe(int s, struct handle_entry *hent, int num_handle );
