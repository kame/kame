#
# $Id: Makefile,v 1.1 2002/02/22 02:58:48 k-sugyou Exp $
#
SRCDIR=	${.CURDIR}/../../kame/had

PROG=	had
SRCS=	haadisc.c halist.c timestamp.c

CPPFLAGS+=-DINET6 -DHAVE_GETIFADDRS

DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a /usr/local/v6/lib/libinet6.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L/usr/local/v6/lib -linet6

MAN=	had.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
