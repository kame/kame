PROG=	altqd
SRCS=	altqd.c libaltq2.c

MAN=	altq.conf.5 altqd.8

CPPFLAGS+=-DALTQ -DINET6 -I${.CURDIR}/../../kame/libaltq

LDADD+=	-L${.CURDIR}/../../lib/libaltq -laltq
DPADD+= ${.CURDIR}/../../lib/libaltq/libaltq.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a
LDADD+=	-lm -lutil
DPADD+=	${LIBM} ${LIBUTIL}

.PATH:	${.CURDIR}/../../kame/altqd

.include <bsd.prog.mk>
