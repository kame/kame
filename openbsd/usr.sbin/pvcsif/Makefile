PROG=	pvcsif
SRCS=	pvcsif.c

MAN=	pvc.4 pvcsif.8

CPPFLAGS+=-DINET6

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/pvcsif

.include <bsd.prog.mk>
