SRCDIR=	${.CURDIR}/../../kame/rtadvd

PROG=	rtadvd
SRCS=	rtadvd.c rrenum.c advcap.c if.c config.c timer.c

CFLAGS+=-DINET6
LDADD+=	-lcompat
DPADD+=	${LIBCOMPAT}
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a \

MAN5=	rtadvd.conf.5
MAN8=	rtadvd.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
