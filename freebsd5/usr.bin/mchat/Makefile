SRCDIR=	${.CURDIR}/../../kame/mchat

PROG=	mchat
SRCS=	mchat.c screen.c history.c

CFLAGS+=-DINET6 -DIPSEC -I${SRCDIR}
LDADD+=	-L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+= ${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+= ${.OBJDIR}/../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=-lcurses -ltermcap
DPADD+=${LIBCURSES} ${LIBTERMCAP}

MAN1=	mchat.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
