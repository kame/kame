.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	libtest

.if ${OPSYS} == "BSD/OS" && (${OPREL} == "3.0" || ${OPREL} == "3.0.1" || ${OPREL} == "3.1")
CC=	shlicc2
LDCC=	${CC}
.endif
CFLAGS+=-Wall -Werror

.if exists(/usr/local/v6/lib/libinet6.a)
LDADD+=-L/usr/local/v6/lib -linet6
DPADD+=/usr/local/v6/lib/libinet6.a
.endif

.include <bsd.prog.mk>
