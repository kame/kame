SRCDIR=	${.CURDIR}/../../kame/mcastread

PROG=	mcastread

CPPFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

MAN=	mcastread.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
