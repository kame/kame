PROG=	rip6admin
MAN8=	rip6admin.8

SRCDIR=	${.CURDIR}/../../../kame/hroute6d/admin
CFLAGS+=	-I${SRCDIR}/../include -DINET6

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
