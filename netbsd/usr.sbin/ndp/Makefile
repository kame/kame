SRCDIR=	${.CURDIR}/../../kame/ndp

.PATH:	${SRCDIR}

PROG=	ndp
SRCS=	ndp.c gmt2local.c
MAN=	ndp.8 # ndp.4

CPPFLAGS+=-DINET6
CPPFLAGS+=-I${SRCDIR}
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

.include <bsd.prog.mk>
