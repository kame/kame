#	$NetBSD: Makefile,v 1.14 1997/05/08 21:11:44 gwr Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/12/93

PROG=	netstat
SRCS=	atalk.c if.c inet.c iso.c main.c mbuf.c mroute.c ns.c route.c \
	tp_astring.c unix.c mroute6.c
SRCS+=	inet6.c
.PATH:	${.CURDIR}/../../sys/netiso
BINGRP=	kmem
BINMODE=2555
LDADD=	-lkvm
DPADD=	${LIBKVM}
CPPFLAGS+= -I${.CURDIR}/../../sys -I${.CURDIR}/../../include
CPPFLAGS+= -DINET6 -DIPSEC
LDFLAGS+= -static

CFLAGS+=	-g -Wall
#CPPFLAGS+=	-DTCP6

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6.obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6.obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
