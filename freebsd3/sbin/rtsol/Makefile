SRCDIR=	${.CURDIR}/../../kame/rtsold

PROG=	rtsol
SRCS=	rtsold.c rtsol.c if.c probe.c dump.c

CFLAGS+=-DINET6 -DHAVE_GETIFADDRS
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

NOMAN=	yes

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
