#	@(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	lpr
CFLAGS+=-I${.CURDIR}/../common_source -DINET6
SRCS=	lpr.c startdaemon.c common.c
BINOWN=	root
BINGRP=	daemon
BINMODE=6555
#BINDIR=	/usr/bin
BINDIR=	/usr/local/v6/bin
MAN1=	lpr.1
.PATH:	${.CURDIR}/../common_source

LDADD+=	-L${.CURDIR}/../../../lib/libinet6 \
	-L${.CURDIR}/../../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include "../../Makefile.inc"
.include <bsd.prog.mk>
