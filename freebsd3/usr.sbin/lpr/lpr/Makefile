#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
#	$Id: Makefile,v 1.7 1998/09/19 22:42:09 obrien Exp $

PROG=	lpr
CFLAGS+=-I${.CURDIR}/../common_source -DINET6 ${CWARNFLAGS}
BINGRP=	daemon
BINMODE=6555
#BINDIR=	/usr/bin
BINDIR=	/usr/local/v6/bin
MAN1=	lpr.1
MAN5=	printcap.5
.PATH:	${.CURDIR}/../common_source
DPADD=	${LIBLPR}
LDADD=	${LIBLPR}
LDADD+= -L${.OBJDIR}/../../../lib/libinet6 \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../../lib/libinet6/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.include "../../Makefile.inc"
.include <bsd.prog.mk>
