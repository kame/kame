PROG=	pvcsif
SRCS=	pvcsif.c

MAN=	pvc.4 pvcsif.8

CPPFLAGS+=-DINET6

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

.PATH:	${.CURDIR}/../../kame/pvcsif

.include <bsd.prog.mk>
