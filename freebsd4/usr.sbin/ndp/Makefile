SRCDIR=	${.CURDIR}/../../kame/ndp

.PATH:	${SRCDIR} ${SRCDIR}/../tcpdump

PROG=	ndp
SRCS=	ndp.c gmt2local.c
MAN8=	ndp.8 # ndp.4

CFLAGS+=-DINET6
CFLAGS+=-I${SRCDIR} -I${SRCDIR}/../tcpdump
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
