#	$NetBSD: Makefile,v 1.7 1995/03/18 14:56:21 cgd Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/5/93

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	ifmcstat
.if (${OPSYS} != "NetBSD")
MAN8=	ifmcstat.8
.else
MAN=	ifmcstat.8
.endif

BINGRP=	kmem
BINMODE=2555
LDADD=	-lkvm
DPADD=	${LIBKVM}

.if (${OPSYS} == NetBSD)
CPPFLAGS+=	-DINET6
.else
CFLAGS+=	-DINET6
.endif
LDADD+=	-L${.OBJDIR}/../../src/libinet6 -L${.OBJDIR}/../../src/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../src/libinet6/libinet6.a \
	${.OBJDIR}/../../src/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
