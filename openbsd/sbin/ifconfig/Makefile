#	$OpenBSD: Makefile,v 1.8 2004/04/27 22:14:11 pb Exp $

PROG=	ifconfig
MAN=	ifconfig.8

CPPFLAGS+=-DINET6

# kame scopeid hack
CPPFLAGS+=-DKAME_SCOPEID

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
