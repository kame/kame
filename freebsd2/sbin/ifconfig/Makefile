#	From: @(#)Makefile	8.1 (Berkeley) 6/5/93
#	$Id: Makefile,v 1.6.2.1 1997/06/30 11:01:57 peter Exp $

PROG=	ifconfig
SRCS=	ifconfig.c
CFLAGS+=-DINET6 -DKAME_SCOPEID

#comment out to exclude SIOC[GS]IFMEDIA support
SRCS+=	ifmedia.c
CFLAGS+=-DUSE_IF_MEDIA

MAN8=	ifconfig.8

DPADD=	${LIBIPX}
LDADD=	-lipx
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
COPTS=	-DNS -Wall -Wmissing-prototypes -Wcast-qual -Wwrite-strings \
	-Wnested-externs

.include <bsd.prog.mk>
