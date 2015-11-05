#define GATT_SERV_GAP 0x1800
#define GATT_SERV_GA 0x1801
#define GATT_SERV_RSC 0x180F
#define GATT_P_SERVDEF 0x2800
#define GATT_S_SERVDEF 0x2801
#define GATT_INCLUDE 0x2802
#define GATT_CHAR 0x2803

struct gatt_char{
  uint8_t property;
  uint16_t handle;
  uint16_t uuid16;
}__attribute__((packed));
#define PROPERTY_BROADCAST 0x01
#define PROPERTY_READ 0x02
#define PROPERTY_WRITENORES 0x4
#define PROPERTY_WRITE 0x8
#define PROPERTY_NOTIFY 0x10
#define PROPERTY_INDICATE 0x20
#define PROPERTY_AUTHWRITE 0x40
#define PROPERTY_EXPROP 0x80
