#	$KAME: Makefile,v 1.6 2000/11/08 06:15:16 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	destest
SRCS=	destest.c des_ecb.c des_setkey.c

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/des

.include <bsd.prog.mk>
