#
# $Id: Makefile,v 1.1 2001/11/21 10:28:21 keiichi Exp $
#
SRCDIR=	${.CURDIR}/../../kame/mip6control

PROG=	mip6control
SRCS=	mip6control.c

CFLAGS+=-DINET6 -Wall

DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a /usr/local/v6/lib/libinet6.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L/usr/local/v6/lib -linet6

MAN8=	mip6control.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
