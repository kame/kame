#	@(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	inetd
MAN8=	inetd.8
MLINKS=	inetd.8 inetd.conf.5

COPTS+=	-Wall -DLOGIN_CAP
#COPTS+=	-DSANITY_CHECK
COPTS+=	-Dss_family=__ss_family -Dss_len=__ss_len -DINET6

DPADD+=	${LIBUTIL}
LDADD+=	-lutil
COPTS+=	-DIPSEC
LDADD+=	-L${.CURDIR}/../../lib/libipsec \
	-L${.CURDIR}/../../lib/libipsec/obj \
	-L/usr/local/v6/lib -lipsec
DPADD+=	${.CURDIR}/../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
