#	$NetBSD: Makefile,v 1.8 2000/01/31 14:20:13 itojun Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/4/93

PROG=	rlogind
MAN=	rlogind.8
CPPFLAGS+=-DINET6
DPADD=	${LIBUTIL}
LDADD=	-lutil
LDADD+= -L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

CPPFLAGS+=	-DINET6

.include <bsd.prog.mk>
