PROG=	faithd
SRCS=	faithd.c tcp.c ftp.c prefix.c

MAN=	faithd.8

LDADD+=	-lutil
DPADD+=	${LIBUTIL}
LDADD+=	-L${.CURDIR}/../../lib/libinet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

.PATH:	${.CURDIR}/../../kame/faithd

.include <bsd.prog.mk>
