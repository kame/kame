PROG=	pvcsif
SRCS=	pvcsif.c

MAN4=	pvc.4
MAN8=	pvcsif.8

CFLAGS+=-DINET6

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/pvcsif

.include <bsd.prog.mk>
