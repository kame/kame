SRCDIR=	${.CURDIR}/../../kame/rip6query

PROG=	rip6query
MAN=	rip6query.8

CPPFLAGS+=	-DINET6 -I${SRCDIR}/../route6d
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
