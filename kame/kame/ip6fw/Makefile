.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	${PREFIX}/sbin

PROG=   ip6fw

LDADD+=	-L${.CURDIR}/../libinet6 \
	-L${.CURDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	-L${.CURDIR}/../libinet6/libinet6.a \
	-L${.CURDIR}/../libinet6/obj/libinet6.a \
	-L/usr/local/v6/lib/libinet6.a

.if (${OPSYS} != "NetBSD")
MAN8=	ip6fw.8
.else
MAN=	ip6fw.8
.endif

.include <bsd.prog.mk>
