#	$NetBSD: Makefile,v 1.12 2000/04/13 07:39:57 itojun Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/5/93

PROG=	ifconfig
MAN=	ifconfig.8

#XXX: set empty strings to LDSTATIC to avoid conflict between libc and libnet6
LDSTATIC=			

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

CPPFLAGS+=-DINET6
CPPFLAGS+=-DHAVE_IFADDRS_H

# KAME scope id hack
CPPFLAGS+=-DKAME_SCOPEID

.include <bsd.prog.mk>
