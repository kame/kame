#	$KAME: Makefile,v 1.1 2000/11/01 14:55:39 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

WARNS?=	0
PROG=	twofishtest
SRCS=	twofishtest.c twofish2.c
MKMAN=	no

CFLAGS+=	-g
.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/twofish

regress:
	@./twofishtest

.include <bsd.prog.mk>
