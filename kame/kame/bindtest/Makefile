.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	bindtest

CFLAGS+=-Wall -Werror

.if exists(/usr/local/v6/lib/libinet6.a)
LDADD+=	-L/usr/local/v6/lib -linet6
DPADD+=	/usr/local/v6/lib/libinet6.a
.endif

.include <bsd.prog.mk>
