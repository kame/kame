SRCDIR=	${.CURDIR}/../../kame/natptd

PROG=	natptd
SRCS=	main.c list.c message.c misc.c

MAN=	natptd.8

CFLAGS+= -g -Wall
CLEANFILES+= natptd.cat8

LDADD+=	-lutil
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
