#	$OpenBSD: Makefile,v 1.6 1999/12/08 07:55:54 itojun Exp $

PROG=	route
MAN=	route.8
SRCS=	route.c show.c keywords.c ccitt_addr.c
BINOWN=	root
BINMODE=555

CPPFLAGS+=	-DINET6

route.o .depend lint tags: keywords.h

#LDADD+=-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
#	-L/usr/local/v6/lib -linet6
#DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
#	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
#	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
