PROG=	ping6
MAN8=	ping6.8

CFLAGS+= -DINET6 -DIPSEC

BINOWN=	root
BINGRP=	bin
BINMODE=4555

LDADD+=	-L${.OBJDIR}/../../lib/libipsec \
	-L/usr/local/v6/lib -lipsec
DPADD+= ${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/ping6

.include <bsd.prog.mk>
