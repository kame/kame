PROG=	altqd
SRCS=	altqd.c if_nameindex.c

MAN=	altq.conf.5 altqd.8

CPPFLAGS+=-DALTQ -DINET6 -I${.CURDIR}/../../kame/libaltq

LDADD+=	-L${.CURDIR}/../../lib/libaltq -L${.CURDIR}/../../lib/libaltq/obj \
	-L/usr/local/v6/lib -laltq
DPADD+= ${.CURDIR}/../../lib/libaltq/libaltq.a \
	${.CURDIR}/../../lib/libaltq/obj/libaltq.a \
	/usr/local/v6/lib/libaltq.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-lm
DPADD+=	${LIBM}

.PATH:	${.CURDIR}/../../kame/altqd

.include <bsd.prog.mk>
