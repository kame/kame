OPSYS!=	uname -s
SYSDIR=	${.CURDIR}/../../../../sys

WARNS?=	1
PROG=	destest
SRCS=	destest.c des_ecb.c des_setkey.c
MKMAN=	no

.if ${OPSYS} == "NetBSD"
CPPFLAGS+=	-I${SYSDIR}
.else
CFLAGS+=	-I${SYSDIR}
.endif

.PATH:	${SYSDIR}/crypto/des

.include <bsd.prog.mk>
