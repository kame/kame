SRCDIR=	${.CURDIR}/../../kame/rip6query

PROG=	rip6query
MAN8=	rip6query.8

CFLAGS+=	-DINET6 -I${SRCDIR}/../route6d
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
