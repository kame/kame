#	$KAME: Makefile,v 1.1 2000/11/01 14:27:57 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

WARNS?=	0
PROG=	rijndaeltest
SRCS=	rijndaeltest.c rijndael-alg-fst.c rijndael-api-fst.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR} "-Dpanic(x)=abort()"
.else
CFLAGS+=	-I${SYSDIR} "-Dpanic(x)=abort()"
.endif

.PATH:	${SYSDIR}/crypto/rijndael

regress:
	@./rijndaeltest

.include <bsd.prog.mk>
