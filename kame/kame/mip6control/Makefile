.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	$(PREFIX)/sbin
PROG=	mip6control

.if (${OPSYS} != "NetBSD")
CFLAGS+=-Wall -DADVAPI=1 -DINET6 -DMIP6
.else
CPPFLAGS+=-DADVAPI=1 -DINET6 -DMIP6
.endif

.if (${OPSYS} != "NetBSD")
MAN8=	mip6control.8
.else
MAN=	mip6control.8
.endif

.include <bsd.prog.mk>
