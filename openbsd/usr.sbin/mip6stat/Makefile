#
# $Id: Makefile,v 1.3 2003/11/27 12:01:54 t-momose Exp $
#
SRCDIR=	${.CURDIR}/../../kame/mip6stat

PROG=	mip6stat
SRCS=	mip6stat.c 

CFLAGS+=-DINET6 -Wall

DPADD+=	${LIBKVM}
LDADD+=	-lkvm

DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6

MAN=	mip6stat.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
