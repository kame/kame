.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	bindtest

CFLAGS+=-Wall -Werror

LDADD+=	-L/usr/local/v6/lib -linet6
DPADD+=	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
