#	@(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	finger
SRCS=	finger.c lprint.c net.c sprint.c util.c

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libine6.a \
	${.CURDIR}/../../lib/libinet6/obj/libine6.a \
	/usr/local/v6/lib/libine6.a

.include <bsd.prog.mk>
