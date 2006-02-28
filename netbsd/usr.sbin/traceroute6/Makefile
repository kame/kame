SRCDIR=	${.CURDIR}/../../kame/traceroute6

PROG=	traceroute6

BINMODE=4555

CPPFLAGS+=-DINET6 -DIPSEC -DUSE_RFC3542
LDADD+=	-L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libinet6 -lipsec -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a

BINOWN=	root
BINMODE=4555

MAN=	traceroute6.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
