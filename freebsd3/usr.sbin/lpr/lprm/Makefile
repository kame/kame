#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
#	$Id: Makefile,v 1.7 1998/09/19 22:42:09 obrien Exp $

PROG=	lprm
CFLAGS+=-I${.CURDIR}/../common_source -DINET6 ${CWARNFLAGS}
.PATH:	${.CURDIR}/../common_source
DPADD=	${LIBLPR}
LDADD=	${LIBLPR}
LDADD+= -L${.OBJDIR}/../../../../src/libinet6 \
        -L${.OBJDIR}/../../../../src/libinet6/obj \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../../../src/libinet6/libinet6.a \
        ${.OBJDIR}/../../../../src/libinet6/obj/libinet6.a \
        /usr/local/v6/lib/libinet6.a

BINGRP=	daemon
BINMODE=6555
#BINDIR=	/usr/bin
BINDIR=	/usr/local/v6/bin

.include "../../Makefile.inc"
.include <bsd.prog.mk>
