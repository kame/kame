SRCDIR=	${.CURDIR}/../../kame/mcastread

PROG=	mcastread

CFLAGS+=-DINET6
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN1=	mcastread.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
