PROG=	ifmcstat
MAN=	ifmcstat.8

BINGRP=	kmem
BINMODE=555
LDADD=	-lkvm
DPADD=	${LIBKVM}

CPPFLAGS+=	-DINET6 -DHAVE_IGMPV3 -DHAVE_MLDV2

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

.PATH:	${.CURDIR}/../../kame/ifmcstat

.include <bsd.prog.mk>
