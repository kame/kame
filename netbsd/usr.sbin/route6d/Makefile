PROG=	route6d
MAN=	route6d.8

CPPFLAGS+=	-Dss_len=__ss_len -Dss_family=__ss_family -DADVAPI -DINET6
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L${.OBJDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	${.OBJDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/route6d

.include <bsd.prog.mk>
