#	$KAME: Makefile,v 1.5 2000/11/08 06:15:16 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	casttest
SRCS=	casttest.c cast128.c

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/cast128

.include <bsd.prog.mk>
