#	$KAME: Makefile,v 1.7 2001/11/07 07:54:02 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	destest
SRCS=	destest.c des_ecb.c des_enc.c des_setkey.c

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/des

.include <bsd.prog.mk>
