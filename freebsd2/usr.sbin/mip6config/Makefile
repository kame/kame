#
# $Id: Makefile,v 1.1 2000/02/08 04:23:08 itojun Exp $
#
SRCDIR=	${.CURDIR}/../../kame/mip6config

PROG=	mip6config
SRCS=	mip6config.c utils.c

CFLAGS+=-DINET6 -Wall

DPADD+=	${LIBKVM}
LDADD+=	-lkvm

DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a /usr/local/v6/lib/libinet6.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L/usr/local/v6/lib -linet6

MAN8=	mip6config.8

afterinstall:
	${INSTALL} -c -o ${BINOWN} -g ${BINGRP} -m 444 \
		${SRCDIR}/mip6.conf.sample ${DESTDIR} ${ETCDIR}

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
