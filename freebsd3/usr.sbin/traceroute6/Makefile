SRCDIR=	${.CURDIR}/../../kame/traceroute6

PROG=	traceroute6

BINOWN=	root
BINGRP=	bin
BINMODE=4555

CFLAGS+=-DINET6 -DIPSEC -DUSE_RFC2292BIS
LDADD+=	-L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN8=	traceroute6.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
