SRCDIR=	${.CURDIR}/../../kame/mcastsend

PROG=	mcastsend

CPPFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

MAN=	mcastsend.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
