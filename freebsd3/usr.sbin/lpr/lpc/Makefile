#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
#	$Id: Makefile,v 1.5 1998/03/07 09:47:57 bde Exp $

PROG=	lpc
CFLAGS+=-I${.CURDIR}/../common_source -DINET6 ${CWARNFLAGS}
MAN8=	lpc.8
SRCS=	lpc.c cmds.c cmdtab.c
BINGRP=	daemon
BINMODE=2555
.PATH:	${.CURDIR}/../common_source
DPADD=	${LIBLPR}
LDADD=	${LIBLPR}
LDADD+= -L${.OBJDIR}/../../../lib/libinet6 \
        -L${.OBJDIR}/../../../lib/libinet6/obj \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../../lib/libinet6/libinet6.a \
        ${.OBJDIR}/../../../lib/libinet6/obj/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
