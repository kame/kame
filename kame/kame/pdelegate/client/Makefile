OPSYS!= uname -s

PROG=	pdelegate
SRCS=	main.c sock.c
.if (${OPSYS} != "NetBSD")
MAN8=	pdelegate.8
.else
MAN=	pdelegate.8
.endif

.PATH:	${.CURDIR}/../common
.if (${OPSYS} != "NetBSD")
CFLAGS+=	-I${.CURDIR}/../common
.else
CPPFLAGS+=	-I${.CURDIR}/../common
.endif

.include <bsd.prog.mk>
