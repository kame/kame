#
# $Id: Makefile,v 1.2 2002/08/27 05:46:42 keiichi Exp $
#
SRCDIR=	${.CURDIR}/../../kame/mip6stat

PROG=	mip6stat
SRCS=	mip6stat.c

CFLAGS+=-DINET6 -Wall -g
BINGRP= kmem
BINMODE=2555
DPADD=  ${LIBKVM}
LDADD=  -lkvm

DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a /usr/local/v6/lib/libinet6.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L/usr/local/v6/lib -linet6

MAN8=	mip6stat.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
