PROG=	route6d
MAN8=	route6d.8

CFLAGS+=	-Dss_len=__ss_len -Dss_family=__ss_family -DADVAPI -DINET6 \
	-DHAVE_GETIFADDRS
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/route6d

.include <bsd.prog.mk>
