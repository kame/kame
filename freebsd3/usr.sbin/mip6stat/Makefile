#
# $Id: Makefile,v 1.2 2000/02/09 13:12:57 itojun Exp $
#
SRCDIR=	${.CURDIR}/../../kame/mip6stat

PROG=	mip6stat
SRCS=	mip6stat.c bcache.c foraddr.c haddr.c halist.c config.c bulist.c

CFLAGS+=-DINET6 -Wall

DPADD+=	${LIBKVM}
LDADD+=	-lkvm

DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a /usr/local/v6/lib/libinet6.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L/usr/local/v6/lib -linet6

MAN8=	mip6stat.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
