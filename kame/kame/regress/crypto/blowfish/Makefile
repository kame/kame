#	$KAME: Makefile,v 1.4 2000/11/08 05:13:50 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

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
