#	$KAME: Makefile,v 1.3 2000/11/08 05:58:25 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	md5test
SRCS=	md5test.c md5.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto

.include <bsd.prog.mk>
