#	From: @(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: src/sbin/ifconfig/Makefile,v 1.10.2.2 1999/12/13 02:02:19 jkh Exp $

PROG=	ifconfig
SRCS=	ifconfig.c

#comment out to exclude SIOC[GS]IFMEDIA support
SRCS+=	ifmedia.c
CFLAGS+=-DUSE_IF_MEDIA -DINET6

#comment out to exclude SIOC[GS]ETVLAN support
SRCS+=	ifvlan.c
CFLAGS+=-DUSE_VLANS

MAN8=	ifconfig.8
DPADD=	${LIBIPX}
LDADD=	-lipx
COPTS=	-DNS -Wall -Wmissing-prototypes -Wcast-qual -Wwrite-strings \
	-Wnested-externs

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

# KAME scopeid hack
CFLAGS+=-DKAME_SCOPEID

.include <bsd.prog.mk>
