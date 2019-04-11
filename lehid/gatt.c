struct service_driver gatt_driver __attribute__((used)) __attribute((section("driver"))) =
{
	.uuid = UUID16(0x1801),
	.init = &gatt_service_init,
	.notify = gatt_service_notify,
};
void gatt_notify(void *sc, int charid, unsigned char *buf, size_t len)
{
	
}
void gatt_service_init(struct service *service, int s)
{
	printf("GATT:%d\n",  service->service_id);	
	return ;
}
