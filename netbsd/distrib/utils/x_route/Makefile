#	$NetBSD: Makefile,v 1.4 1999/02/13 02:54:19 lukem Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/5/93

PROG=	route
MKMAN=	no
SRCS=   route.c show.c keywords.c ccitt_addr.c

SRCDIR= ${.CURDIR}/../../../sbin/route
#CPPFLAGS+= -DSMALL -I${SRCDIR}
CPPFLAGS+= -I${.CURDIR}/../../../sys -I${.CURDIR}/../../../include -DINET6
COPTS+= -g

BINOWN=	root
BINMODE=4555

all: ${PROG}

.include <bsd.prog.mk>

.PATH:  ${SRCDIR}
