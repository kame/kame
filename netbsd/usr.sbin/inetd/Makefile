#	from: @(#)Makefile	8.1 (Berkeley) 6/6/93
#	$NetBSD: Makefile,v 1.14 1997/10/25 06:58:06 lukem Exp $

PROG=	inetd
SRCS=	inetd.c
MAN=	inetd.8
MLINKS=	inetd.8 inetd.conf.5

CPPFLAGS+=-DLIBWRAP
# Use LIBWRAP_INTERNAL for libwrap checking of inetd's `internal' services.
#CPPFLAGS+=-DLIBWRAP_INTERNAL
LDADD+=	-L${.CURDIR}/../../lib/libwrap -L${.CURDIR}/../../lib/libwrap/obj \
	-L/usr/local/v6/lib -lwrap
DPADD+=	${.CURDIR}/../../lib/libwrap/libwrap.a \
	${.CURDIR}/../../lib/libwrap/obj/libwrap.a \
	/usr/local/v6/lib/libwrap.a

# This is necessary due to be friendly with past API changes... DAMN.
CPPFLAGS+=-Dss_family=__ss_family -Dss_len=__ss_len

CFLAGS+=-DINET6
CFLAGS+=-I${.CURDIR}/../../lib/libipsec
LDADD+= -L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libipsec/obj \
	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.CURDIR}/../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

SRCDIR=	${.CURDIR}/../../kame/inetd
.PATH:	${SRCDIR}
CFLAGS+=-DIPSEC
SRCS+=	ipsec.c
CPPFLAGS+=-I${SRCDIR}

.include <bsd.prog.mk>
