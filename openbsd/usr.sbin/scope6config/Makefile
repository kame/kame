SRCDIR=	${.CURDIR}/../../kame/scope6config
.PATH:	${SRCDIR}

PROG=	scope6config
CPPFLAGS+=	-DINET6
NOMAN=	yes

LDADD+=	-L${.CURDIR}/../libinet6 -L${.CURDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../libinet6/libinet6.a \
	${.CURDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
