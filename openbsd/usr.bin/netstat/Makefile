#	$OpenBSD: Makefile,v 1.9 2000/06/14 01:05:04 itojun Exp $

PROG=	netstat
SRCS=	if.c inet.c ipx.c iso.c main.c mbuf.c mroute.c ns.c route.c \
	tp_astring.c unix.c atalk.c inet6.c mroute6.c
.PATH:	${.CURDIR}/../../sys/netiso
BINGRP=	kmem
BINMODE=2555
LDADD=	-lkvm
DPADD=	${LIBKVM}
INET6?=	yes

.if (${INET6} != "no")
CPPFLAGS+=	-DINET6
.endif

CPPFLAGS+=	-DKAME_SCOPEID

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
