#	$OpenBSD: Makefile,v 1.2 1996/06/26 05:33:14 deraadt Exp $

PROG=	finger
SRCS=	finger.c lprint.c net.c sprint.c util.c

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
