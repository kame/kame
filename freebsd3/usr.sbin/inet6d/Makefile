SRCDIR=	${.CURDIR}/../../kame/inet6d

PROG=	inet6d

LDADD+=	-lutil
DPADD+=	${LIBUTIL}
CFLAGS+= -DIPSEC -DINET6
LDADD+=	-L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN8=	inet6d.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
