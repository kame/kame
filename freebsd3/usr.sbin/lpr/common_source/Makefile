# $FreeBSD: src/usr.sbin/lpr/common_source/Makefile,v 1.4.2.1 1999/08/29 15:43:07 peter Exp $

#
# Library of internal routines for the print spooler suite.
# Originally these were compiled separately into each program,
# but the library makes it much easier to modularize them.
#
LIB=		lpr
SRCS=		common.c displayq.c net.c printcap.c request.c rmjob.c \
		startdaemon.c
NOMAN=		noman
NOPROFILE=	noprofile
NOPIC=		nopic
CFLAGS+=	-DINET6 ${CWARNFLAGS}

install:

.include <bsd.lib.mk>
