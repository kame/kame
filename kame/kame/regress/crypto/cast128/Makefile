#	$KAME: Makefile,v 1.3 2000/11/08 05:13:50 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

PROG=	casttest
SRCS=	casttest.c cast128.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/cast128

regress:
	@${.OBJDIR}/${PROG}

.include <bsd.prog.mk>
