PROG=	pvctxctl
SRCS=	pvctxctl.c

MAN8=	pvctxctl.8

.PATH:	${.CURDIR}/../../kame/pvcsif

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
