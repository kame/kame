.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	$(PREFIX)/sbin
PROG=	mip6control

MIP6CONTROL_DEF=-DADVAPI=1 -DINET6 -DMIP6

BINGRP= kmem
BINMODE=2555
LDADD=  -lkvm
DPADD=  ${LIBKVM}

.if (${OPSYS} != "NetBSD")
CFLAGS+=-Wall ${MIP6CONTROL_DEF}
.else
CPPFLAGS+=${MIP6CONTROL_DEF}
.endif

.if (${OPSYS} != "NetBSD")
MAN8=	mip6control.8
.else
MAN=	mip6control.8
.endif

.include <bsd.prog.mk>
