#	$OpenBSD: Makefile,v 1.7 2000/04/14 02:40:01 itojun Exp $

PROG=	ifconfig
MAN=	ifconfig.8

#XXX set empty strings to LDSTATIC to avoid conflict between libc and lbinet6.
LDSTATIC=

CPPFLAGS+=-DINET6
CPPFLAGS+=-DHAVE_IFADDRS_H

# kame scopeid hack
CPPFLAGS+=-DKAME_SCOPEID

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
