SRCDIR=	${.CURDIR}/../../kame/natptlog

PROG=	natptlog
SRCS=	natptlog.c

MAN8=	natptlog.8

CFLAGS+= -g -Wall

LDADD+=	-lutil
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
