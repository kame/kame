SRCDIR=	${.CURDIR}/../../kame/mchat

PROG=	mchat
SRCS=	mchat.c screen.c history.c

CFLAGS+=-DINET6 -DIPSEC -I${SRCDIR}
CFLAGS+=-Dss_family=__ss_family -Dss_len=__ss_len
LDADD+=	-L${.OBJDIR}/../../lib/libipsec \
	-L/usr/local/v6/lib -lipsec -lcurses
DPADD+= ${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=-lcurses -ltermcap
DPADD+=${LIBCURSES} ${LIBTERMCAP}

MAN1=	mchat.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
