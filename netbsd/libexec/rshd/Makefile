#	$NetBSD: Makefile,v 1.11 2000/01/31 14:20:14 itojun Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/4/93

PROG=	rshd
MAN=	rshd.8

CPPFLAGS+=-DLOGIN_CAP
LDADD+= -lutil

CPPFLAGS+=-DINET6
LDADD+= -L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
