#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: src/usr.sbin/lpr/lpc/Makefile,v 1.7 1999/08/28 01:16:50 peter Exp $

PROG=	lpc
CFLAGS+=-I${.CURDIR}/../common_source ${CWARNFLAGS}
MAN8=	lpc.8
SRCS=	lpc.c cmds.c cmdtab.c
BINGRP=	daemon
BINMODE=2555
.PATH:	${.CURDIR}/../common_source
DPADD=	${LIBLPR} ${LIBEDIT} ${LIBTERMCAP}
LDADD=	${LIBLPR} -ledit -ltermcap
LDADD+=	-L${.OBJDIR}/../../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
