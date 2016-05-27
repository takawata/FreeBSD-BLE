PROG=lehid
CFLAGS+=-I/usr/local/include
SRCS=main.c send_recv.c sql.c servicename.c hogp.c
LDFLAGS+= -L/usr/local/lib
LDADD=-lbluetooth -lcrypto -lusbhid -lsqlite3
NO_MAN=yes
CFLAGS+= -g
.include <bsd.prog.mk>
