PROG = fetch
SRCS = file.c ftp.c http.c main.c util.c uri.c

CFLAGS+=	-Wall -Wwrite-strings -Wmissing-prototypes -DINET6 -g

DPADD=  ${LIBFTPIO} ${LIBMD}
LDADD=  -L${.CURDIR}/../../lib/libftpio -L${.CURDIR}/../../lib/ftpio/obj \
	-lftpio -lmd
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
