#	$KAME: Makefile,v 1.3 2000/11/01 15:28:10 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

WARNS?=	1
PROG=	bftest
SRCS=	bftest.c bf_enc.c bf_skey.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/blowfish

regress:
	@${.OBJDIR}/${PROG}

.include <bsd.prog.mk>
