OPSYS!= uname -s

PROG=	pdelegated
SRCS=	main.c sock.c

NOMAN=	yes

.PATH:	${.CURDIR}/../common
.if (${OPSYS} != "NetBSD")
CFLAGS+=	-I${.CURDIR}/../common
.else
CPPFLAGS+=	-I${.CURDIR}/../common
.endif

.include <bsd.prog.mk>
