PROG=lehid
PREFIX?= /usr/local
BINDIR= ${PREFIX}/sbin
MANDIR= ${PREFIX}/man/man
LIBDIR= ${PREFIX}/lib
CFLAGS+= -I${PREFIX}/include
LDFLAGS+= -L${PREFIX}/lib

SRCS+= applewatch.c
SRCS+= att.c
SRCS+= batt.c
SRCS+= cadence.c
SRCS+= dis.c
SRCS+= event.c
SRCS+= gap.c
SRCS+= hogp.c
SRCS+= hrp.c
SRCS+= lightbulb.c
SRCS+= main.c
SRCS+= microbit-mag.c
SRCS+= microbit-temp.c
SRCS+= notify.c
SRCS+= omron_sensor.c
SRCS+= pasori.c
SRCS+= rcs.c
SRCS+= send_recv.c
SRCS+= service.c
SRCS+= servicename.c
SRCS+= sql.c
SRCS+= uuid.c
#SRCS+= microbit-accel.c

LDADD=-lbluetooth -lcrypto -lusbhid -lsqlite3
MK_MAN=no

.if !defined(WITHOUT_DEBUG)
CFLAGS+= -g
.endif

.if !defined(WITHOUT_ALSA)
SRCS+= midi.c
LDADD+= -lasound
.endif

.include <bsd.prog.mk>
