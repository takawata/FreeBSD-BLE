PROG=le_enable
PREFIX?= /usr/local
BINDIR= ${PREFIX}/sbin
MANDIR= ${PREFIX}/man/man
LIBDIR= ${PREFIX}/lib
SRCS=le_enable.c send_recv.c gap.c
LDADD=-lbluetooth -lcrypto -lusbhid
MK_MAN=no
.if !defined(WITHOUT_DEBUG)
CFLAGS+= -g
.endif
.include <bsd.prog.mk>
