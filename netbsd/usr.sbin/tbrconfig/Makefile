PROG=	tbrconfig
SRCS=	tbrconfig.c

MAN=	tbrconfig.8

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

.PATH:	${.CURDIR}/../../kame/tbrconfig

.include <bsd.prog.mk>
