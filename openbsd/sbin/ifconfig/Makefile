#	$OpenBSD: Makefile,v 1.3 1997/09/21 11:36:46 deraadt Exp $

PROG=	ifconfig
MAN=	ifconfig.8

CPPFLAGS+=-DINET6

CPPFLAGS+=-DKAME_SCOPEID
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
