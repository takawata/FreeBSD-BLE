PROG=lehid
PREFIX?= /usr/local
BINDIR= ${PREFIX}/sbin
MANDIR= ${PREFIX}/man/man
LIBDIR= ${PREFIX}/lib
CFLAGS+=-I${PREFIX}/include
SRCS=main.c send_recv.c sql.c servicename.c hogp.c batt.c uuid.c gap.c dis.c rcs.c service.c notify.c att.c event.c pasori.c applewatch.c midi.c microbit-temp.c microbit-mag.c lightbulb.c hrp.c cadence.c omron_sensor.c #microbit-accel.c 
LDFLAGS+= -L${PREFIX}/lib
LDADD=-lbluetooth -lcrypto -lusbhid -lsqlite3
MK_MAN=no
.if !defined(WITHOUT_DEBUG)
CFLAGS+= -g
.endif
.include <bsd.prog.mk>
