SRCDIR=	${.CURDIR}/../../kame/natptlog

PROG=	natptlog
SRCS=	natptlog.c showsubs.c

MAN8=	natptlog.8

CFLAGS+= -g -Wall

LDADD+=	-lutil
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR} ${SRCDIR}/../natptconfig

.include <bsd.prog.mk>
