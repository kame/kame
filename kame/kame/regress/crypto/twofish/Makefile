#	$KAME: Makefile,v 1.4 2000/11/08 05:13:51 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

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
