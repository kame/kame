#	from: @(#)Makefile	8.1 (Berkeley) 6/4/93
#	$Id: Makefile,v 1.2 1996/07/16 17:55:42 millert Exp $

PROG=	fingerd
MAN=	fingerd.8

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
