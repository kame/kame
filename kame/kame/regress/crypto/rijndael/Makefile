#	$KAME: Makefile,v 1.2 2000/11/01 15:28:11 itojun Exp $

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
	@${.OBJDIR}/${PROG}

.include <bsd.prog.mk>
