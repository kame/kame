.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	libtest

.if (${OPSYS} == "BSD/OS")
CC=	shlicc2
LDCC=	${CC}
.endif
CFLAGS+=-Wall -Werror

.include <bsd.prog.mk>
