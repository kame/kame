SRCDIR=	${.CURDIR}/../../kame/ip6fw

PROG=   ip6fw

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN8=	ip6fw.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
