#	$KAME: Makefile,v 1.4 2000/11/08 06:15:16 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	md5test
SRCS=	md5test.c md5.c

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto

.include <bsd.prog.mk>
