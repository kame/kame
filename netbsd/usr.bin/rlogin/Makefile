#	$NetBSD: Makefile,v 1.12 1999/02/18 21:22:51 scottr Exp $
#	@(#)Makefile	8.1 (Berkeley) 7/19/93

PROG=	rlogin
SRCS=	rlogin.c

BINOWN=	root
BINMODE=4555
#INSTALLFLAGS=-fschg

CPPFLAGS+= -DINET6
DPADD+=	${LIBEDIT} ${LIBTERMCAP}

LDADD+= -L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
