#	$NetBSD: Makefile,v 1.4 1997/10/19 08:13:23 mrg Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	finger
SRCS=	finger.c lprint.c net.c sprint.c util.c

CPPFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
