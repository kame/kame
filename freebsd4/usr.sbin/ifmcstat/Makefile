PROG=	ifmcstat
MAN8=	ifmcstat.8

BINGRP=	kmem
BINMODE=555
LDADD=	-lkvm
DPADD=	${LIBKVM}

CFLAGS+=	-DINET6 -DHAVE_IGMPV3 -DHAVE_MLDV2

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/ifmcstat

.include <bsd.prog.mk>
