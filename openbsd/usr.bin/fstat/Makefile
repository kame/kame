#	$OpenBSD: Makefile,v 1.8 2001/06/27 06:16:49 art Exp $

PROG=	fstat
DPADD=	${LIBKVM}
SRCS=	fstat.c isofs.c
LDADD=	-lkvm
BINGRP=	kmem
BINMODE=2555

CFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
