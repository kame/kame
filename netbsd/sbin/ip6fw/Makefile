SRCDIR=	${.CURDIR}/../../kame/ip6fw

PROG=   ip6fw

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN=	ip6fw.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
