#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: src/usr.sbin/lpr/lpd/Makefile,v 1.10 1999/08/28 01:16:52 peter Exp $

PROG=	lpd
CFLAGS+=-I${.CURDIR}/../common_source ${CWARNFLAGS}
MAN8=	lpd.8
SRCS=	lpd.c printjob.c recvjob.c lpdchar.c modes.c
DPADD=	${LIBLPR}
LDADD=	${LIBLPR}
LDADD+= -L${.OBJDIR}/../../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
