PROG=	faithd
SRCS=	faithd.c tcp.c ftp.c prefix.c

MAN8=	faithd.8

LDADD+=	-lutil
DPADD+=	${LIBUTIL}
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/faithd

.include <bsd.prog.mk>
