#	$NetBSD: Makefile,v 1.7 1995/03/18 14:56:21 cgd Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/5/93

PROG=	ifconfig
MAN=	ifconfig.8

CPPFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

# kame NI_WITHSCOPEID hack
CPPFLAGS+=-DKAME_SCOPEID

CFLAGS+=	-g
.include <bsd.prog.mk>
