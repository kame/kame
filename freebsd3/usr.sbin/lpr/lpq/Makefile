#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: src/usr.sbin/lpr/lpq/Makefile,v 1.6.2.1 1999/08/29 15:43:26 peter Exp $

PROG=	lpq
CFLAGS+=-I${.CURDIR}/../common_source -DINET6 ${CWARNFLAGS}
DPADD=	${LIBLPR}
LDADD=	${LIBLPR}
LDADD+= -L${.OBJDIR}/../../../lib/libinet6 \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../../lib/libinet6/libinet6.a \
        /usr/local/v6/lib/libinet6.a

BINGRP=	daemon
BINMODE=6555
#BINDIR=	/usr/bin
BINDIR=	/usr/local/v6/bin

.include "../../Makefile.inc"
.include <bsd.prog.mk>
