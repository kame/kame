PROG=	altqd
SRCS=	altqd.c

MAN5=	altq.conf.5
MAN8=	altqd.8

CFLAGS+=-DALTQ -DINET6 -I${.CURDIR}/../../kame/libaltq

LDADD+=	-L${.OBJDIR}/../../lib/libaltq \
	-L/usr/local/v6/lib -laltq
DPADD+= ${.OBJDIR}/../../lib/libaltq/libaltq.a \
	/usr/local/v6/lib/libaltq.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-lm
DPADD+=	${LIBM}

.PATH:	${.CURDIR}/../../kame/altqd

.include <bsd.prog.mk>
