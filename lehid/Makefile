PROG=lehid
CFLAGS+=-I/usr/local/include
SRCS=main.c send_recv.c sql.c servicename.c hogp.c batt.c uuid.c gap.c dis.c rcs.c service.c notify.c att.c event.c pasori.c applewatch.c midi.c microbit-temp.c microbit-mag.c lightbulb.c hrp.c cadence.c omron_sensor.c #microbit-accel.c 
LDFLAGS+= -L/usr/local/lib
LDADD=-lbluetooth -lcrypto -lusbhid -lsqlite3
NO_MAN=yes
CFLAGS+= -g
.include <bsd.prog.mk>
