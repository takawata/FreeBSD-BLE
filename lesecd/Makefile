PROG=lesecd
PREFIX?= /usr/local
BINDIR= ${PREFIX}/sbin
MANDIR= ${PREFIX}/man/man
LIBDIR= ${PREFIX}/lib
SRCS=lesecd.c lexer.l parser.y
LDADD=-lbluetooth -lcrypto
MK_MAN=no
.if !defined(WITHOUT_DEBUG)
CFLAGS+= -g
.endif
.include <bsd.prog.mk>
