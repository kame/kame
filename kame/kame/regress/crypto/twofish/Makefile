#	$KAME: Makefile,v 1.6 2000/11/08 06:15:17 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	twofishtest
SRCS=	twofishtest.c twofish2.c

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/twofish

.include <bsd.prog.mk>
