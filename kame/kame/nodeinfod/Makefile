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

.if ${OPSYS} == "BSD/OS"
CFLAGS+=-DHAVE_OPENSSL_MD5_H -I/usr/contrib/include
LDADD+=	-L/usr/contrib/lib -lcrypto -L/usr/local/v6/lib -linet6
DPADD+=	/usr/contrib/lib/libcrypto.a /usr/local/v6/lib/libinet6.a
.elif ${OPSYS} == "NetBSD"
CPPFLAGS+=-DHAVE_MD5_H
.elif ${OPSYS} == "FreeBSD"
CPPFLAGS+=-DHAVE_MD5_H
LDADD+=	-lcrypt -L/usr/local/v6/lib -linet6
DPADD+=	${LIBCRYPT} /usr/local/v6/lib/libinet6.a
.else
CFLAGS+=-DHAVE_MD5_H
.endif

WARNS?=	1

.include <bsd.prog.mk>
