PROG=   ip6fw

COPTS+=	-Wall
LDADD+=	-L${.CURDIR}/../../src/libinet6 \
	-L${.CURDIR}/../../src/libinet6/obj \
	-L/usr/local/v6/lib -linet6

MAN8=	ip6fw.8

.include <bsd.prog.mk>
