#	$NetBSD: Makefile,v 1.10 1999/02/24 19:31:38 jwise Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/5/93

PROG=	ping
MAN=	ping.8
BINOWN=	root
BINMODE=4555
LDADD=	-lm
CPPFLAGS+=	-DIPSEC
LDADD+= -L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libipsec/obj \
	-L/usr/local/v6/lib -lipsec
LDADD+= -L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6

.include <bsd.prog.mk>
