#	$KAME: Makefile,v 1.5 2000/11/08 06:15:17 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	rijndaeltest
SRCS=	rijndaeltest.c rijndael-alg-fst.c rijndael-api-fst.c

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR} "-Dpanic(x)=abort()"
.else
CFLAGS+=	-I${SYSDIR} "-Dpanic(x)=abort()"
.endif

.PATH:	${SYSDIR}/crypto/rijndael

BENCHROUNDS=	100

.include <bsd.prog.mk>
