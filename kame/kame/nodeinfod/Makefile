.include "../Makefile.opsys"

PROG=	nodeinfod
SRCS=	nodeinfod.c

.if (${OPSYS} == "NetBSD" || ${OPSYS} == "OpenBSD")
MAN=	nodeinfod.8
.elif ${OPSYS} == "BSD/OS"
MAN8=	nodeinfod.0
.else
MAN8=	nodeinfod.8
.endif

WARNS?=	1

.include <bsd.prog.mk>
