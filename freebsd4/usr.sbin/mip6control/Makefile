#
# $Id: Makefile,v 1.3 2003/11/25 10:02:57 keiichi Exp $
#
SRCDIR=	${.CURDIR}/../../kame/mip6control

PROG=	mip6control
SRCS=	mip6control.c

CFLAGS+=-DINET6 -Wall -g
BINGRP= kmem
BINMODE=2555
DPADD=  ${LIBKVM}
LDADD=  -lkvm

DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a /usr/local/v6/lib/libinet6.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L/usr/local/v6/lib -linet6

MAN8=	mip6control.8

.PATH:	${SRCDIR}

afterinstall:
	${INSTALL} -c -m 755 \
		${SRCDIR}/mip6makeconfig.sh \
		${BINDIR}
	${INSTALL} -c -m 755 \
		${SRCDIR}/mip6seccontrol.sh \
		${BINDIR}
 
.include <bsd.prog.mk>
