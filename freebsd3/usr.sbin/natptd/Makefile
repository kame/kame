SRCDIR=	${.CURDIR}/../../kame/natptd

PROG=	natptd
SRCS=	main.c list.c message.c misc.c

MAN8=	natptd.8

CFLAGS+= -g -Wall

LDADD+=	-lutil
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
