PROG=lepair
PREFIX?= /usr/local
BINDIR= ${PREFIX}/sbin
MANDIR= ${PREFIX}/man/man
LIBDIR= ${PREFIX}/lib
SRCS=lepair.c send_recv.c
CFLAGS+= -I${PREFIX}/include
LDFLAGS+= -L${PREFIX}/lib
LDADD=-lbluetooth -lcrypto
MK_MAN=no
.if !defined(WITHOUT_DEBUG)
CFLAGS+= -g
.endif
.include <bsd.prog.mk>
