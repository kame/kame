SRCDIR=	${.CURDIR}/../../kame/mchat

PROG=	mchat
SRCS=	mchat.c screen.c history.c

CPPFLAGS+=-DINET6 -DIPSEC -I${SRCDIR}
CPPFLAGS+=-Dss_family=__ss_family -Dss_len=__ss_len
LDADD+=	-L${.OBJDIR}/../../libipsec -L${.OBJDIR}/../../libipsec/obj \
	-L/usr/local/v6/lib -lipsec -lcurses
DPADD+= ${.OBJDIR}/../../libipsec/libipsec.a \
	${.OBJDIR}/../../libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.OBJDIR}/../../libinet6 -L${.OBJDIR}/../../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=-lcurses -ltermcap
DPADD+=${LIBCURSES} ${LIBTERMCAP}

MAN=	mchat.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
