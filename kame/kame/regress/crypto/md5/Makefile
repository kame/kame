#	$KAME: Makefile,v 1.1 2000/11/02 00:06:26 itojun Exp $

.include "../Makefile.inc"
.include <bsd.own.mk>

# XXX we may want to test md5 routines in libkern, for platforms ships
# md5 routines with libkern.
WARNS?=	1
PROG=	md5test
SRCS=	md5test.c md5.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto

regress:
	@${.OBJDIR}/${PROG}

.include <bsd.prog.mk>
