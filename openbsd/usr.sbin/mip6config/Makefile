#
# $Id: Makefile,v 1.2 2000/02/09 13:16:29 itojun Exp $
#
SRCDIR=	${.CURDIR}/../../kame/mip6config

PROG=	mip6config
SRCS=	mip6config.c utils.c

CFLAGS+=-DINET6 -Wall

DPADD+=	${LIBKVM}
LDADD+=	-lkvm

DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6

MAN=	mip6config.8

afterinstall:
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 444 \
		${SRCDIR}/mip6.conf.sample ${DESTDIR} ${ETCDIR}

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
