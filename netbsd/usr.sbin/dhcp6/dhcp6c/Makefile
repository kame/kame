#	from: @(#)Makefile	8.1 (Berkeley) 6/6/93
#	$NetBSD: Makefile,v 1.14 1997/10/25 06:58:06 lukem Exp $

PROG=	dhcp6c
SRCS=	dhcp6c.c common.c dhcp6opt.c
MAN=	dhcp6c.8

LDADD+= -L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>

.PATH:	${SRCDIR}
