SRCDIR=	${.CURDIR}/../../kame/traceroute6

PROG=	traceroute6

BINOWN=	root
BINGRP=	bin
BINMODE=4555

CFLAGS+=-DINET6 -DIPSEC
LDADD+=	-L${.OBJDIR}/../../lib/libipsec \
	-L/usr/local/v6/lib -lipsec
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN8=	traceroute6.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
