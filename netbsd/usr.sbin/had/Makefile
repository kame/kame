#
# $Id: Makefile,v 1.3 2003/04/11 11:30:46 t-momose Exp $
#
SRCDIR=	${.CURDIR}/../../kame/had

PROG=	had
SRCS=	haadisc.c halist.c timestamp.c mpa.c

CPPFLAGS+=-DINET6 -DHAVE_GETIFADDRS

DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a /usr/local/v6/lib/libinet6.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L/usr/local/v6/lib -linet6 -lkvm

MAN=	had.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
