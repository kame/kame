OPSYS!= uname -s

PROG=	pdelegate
SRCS=	main.c sock.c
.if (${OPSYS} != "NetBSD")
MAN8=	pdelegate.8
.else
MAN=	pdelegate.8
.endif

.PATH:	${.CURDIR}/../common
CPPFLAGS+=	-I${.CURDIR}/../common

.include <bsd.prog.mk>
