SRCDIR=	${.CURDIR}/../../kame/rtadvd

PROG=	rtadvd
SRCS=	rtadvd.c rrenum.c advcap.c if.c config.c timer.c dump.c

CPPFLAGS+=-DINET6 -DROUTEINFO -DHAVE_POLL_H
LDADD+=	-lutil
DPADD+=	${LIBUTIL}
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6 -lcompat
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${LIBCOMPAT}
MAN=	rtadvd.8 rtadvd.conf.5

.PATH:	${SRCDIR}

CFLAGS+=	-Wall -Werror -Wmissing-prototypes

.include <bsd.prog.mk>
