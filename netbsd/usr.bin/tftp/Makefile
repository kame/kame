#	$NetBSD: Makefile,v 1.6 1999/07/12 20:19:20 itojun Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	tftp
SRCS=	main.c tftp.c tftpsubs.c

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
