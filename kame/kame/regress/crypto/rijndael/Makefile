#	$KAME: Makefile,v 1.3 2000/11/08 05:13:51 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

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
