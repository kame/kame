SRCDIR=	${.CURDIR}/../../kame/mchat

PROG=	mchat
SRCS=	mchat.c screen.c history.c

CPPFLAGS+=-DINET6 -DIPSEC -I${SRCDIR}
LDADD+=	-L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libinet6 \
	-lipsec -linet6
DPADD+= ${.CURDIR}/../../lib/libipsec/libipsec.a
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a
LDADD+=-lcurses -ltermcap
DPADD+=${LIBCURSES} ${LIBTERMCAP}

MAN=	mchat.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
