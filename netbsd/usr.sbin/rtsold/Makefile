SRCDIR=	${.CURDIR}/../../kame/rtsold

PROG=	rtsold
SRCS=	rtsold.c rtsol.c if.c probe.c dump.c rtsock.c

CPPFLAGS+=-DINET6 -DUSE_RTSOCK -DHAVE_POLL_H
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a

MAN=	rtsold.8
MLINKS=	rtsold.8 rtsol.8

.PATH:	${SRCDIR}

LDADD+=	-lutil
DPADD+=	${LIBUTIL}

.include <bsd.prog.mk>
