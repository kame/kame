#	$KAME: Makefile,v 1.3 2000/11/01 15:28:11 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

WARNS?=	0
PROG=	twofishtest
SRCS=	twofishtest.c twofish2.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/twofish

regress:
	@${.OBJDIR}/${PROG}

.include <bsd.prog.mk>
