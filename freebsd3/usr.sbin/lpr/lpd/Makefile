#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
#	$Id: Makefile,v 1.9 1998/09/11 18:49:32 wollman Exp $

PROG=	lpd
CFLAGS+=-I${.CURDIR}/../common_source -DINET6 ${CWARNFLAGS}
MAN8=	lpd.8
SRCS=	lpd.c printjob.c recvjob.c lpdchar.c modes.c
DPADD=	${LIBLPR}
LDADD=	${LIBLPR}
LDADD+= -L${.OBJDIR}/../../../../src/libinet6 \
        -L${.OBJDIR}/../../../../src/libinet6/obj \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../../../src/libinet6/libinet6.a \
        ${.OBJDIR}/../../../../src/libinet6/obj/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
