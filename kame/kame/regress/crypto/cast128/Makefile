#	$KAME: Makefile,v 1.1 2000/11/01 14:03:37 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

WARNS?=	1
PROG=	casttest
SRCS=	casttest.c cast128.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/cast128

regress:
	@./casttest

.include <bsd.prog.mk>
