.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	libtest

.if ${OPSYS} == "BSD/OS" && (${OPREL} == "3.0" || ${OPREL} == "3.0.1" || ${OPREL} == "3.1")
CC=	shlicc2
LDCC=	${CC}
.endif
CFLAGS+=-Wall -Werror

#LDADD+=-L/usr/local/v6/lib -linet6
#DPADD+=/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
