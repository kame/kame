SRCDIR=	${.CURDIR}/../../kame/prefix

PROG=	prefix
SRCS=	prefix.c

MAN8=	prefix.8

CFLAGS+=-g
CFLAGS+=-DINET6
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
