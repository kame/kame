SRCDIR=	${.CURDIR}/../../../kame/racoon

CFLAGS+=-g -O2
OPTFLAG+=-DHAVE_PFKEYV2 -DYIPS_DEBUG
CFLAGS+=-DINET6 -DHAVE_FUNCTION_MACRO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBL=1 -DHAVE_LIBY=1 -DENABLE_IPV6=1 -DADVAPI=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_VARARGS_H=1 -DTIME_WITH_SYS_TIME=1 -DRETSIGTYPE=void -DHAVE_VPRINTF=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 -DHAVE_STRERROR=1 -DHAVE_STRTOL=1 -DHAVE_STRTOUL=1 -DHAVE_STRDUP=1  $(OPTFLAG) -DIPSEC -I. -I$(SRCDIR) -Dss_family=__ss_family -Dss_len=__ss_len -DSYSCONFDIR=\"$(ETCDIR)\"
CFLAGS+=-DYY_NO_UNPUT
CFLAGS+=-I/usr/local/include
YFLAGS+=-d

.if exists(/usr/local/include/rc5.h) || exists(/usr/local/ssl/include/rc5.h) || exists(/usr/local/ssl/include/openssl/rc5.h)
CFLAGS+=-DHAVE_RC5_H=1
.endif
.if exists(/usr/local/include/idea.h) || exists(/usr/local/ssl/include/idea.h) || exists(/usr/local/ssl/include/openssl/idea.h)
CFLAGS+=-DHAVE_IDEA_H=1
.endif
.if exists(/usr/local/include/openssl)
CFLAGS+=-I/usr/local/include/openssl
.elif exists(/usr/local/include/ssleay)
CFLAGS+=-I/usr/local/include/ssleay
.elif exists(/usr/local/ssl/include)
CFLAGS+=-I/usr/local/ssl/include
.if exists(/usr/local/ssl/include/openssl)
CFLAGS+=-I/usr/local/ssl/include/openssl
.endif
.endif

.if exists(/usr/local/ssl/bin/openssl)
ssleay_cmd=/usr/local/ssl/bin/openssl
.elif exists(/usr/pkg/ssl/bin/openssl)
ssleay_cmd=/usr/pkg/ssl/bin/openssl
.elif exists(/usr/local/bin/openssl)
ssleay_cmd=/usr/local/bin/openssl
.elif exists(/usr/local/ssl/bin/ssleay)
ssleay_cmd=/usr/local/ssl/bin/ssleay
.elif exists(/usr/pkg/ssl/bin/ssleay)
ssleay_cmd=/usr/pkg/ssl/bin/ssleay
.elif exists(/usr/local/bin/ssleay)
ssleay_cmd=/usr/local/bin/ssleay
.else
ssleay_cmd=openssl
.endif

LDADD+=	-ly -ll
DPADD+=	${LIBY} ${LIBL}
LDADD+=	-L${.CURDIR}/../../../lib/libipsec \
	-L${.CURDIR}/../../../lib/libipsec/obj \
	-L${.CURDIR}/../../../lib/libinet6 \
	-L${.CURDIR}/../../../lib/libinet6/obj \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.CURDIR}/../../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	-L${.CURDIR}/../../../lib/libinet6/libinet6.a \
	-L${.CURDIR}/../../../lib/libinet6/obj/libinet6.a \
	-L/usr/local/v6/lib/libinet6.a
.if exists(/usr/local/lib/libcrypto.a)
LDADD+=	-L/usr/local/lib -lcrypto
DPADD+=	/usr/local/lib/libcrypto.a
.elif exists(/usr/local/ssl/lib/libcrypto.a)
LDADD+=	-L/usr/local/ssl/lib -lcrypto
DPADD+=	/usr/local/ssl/lib/libcrypto.a
.endif

.PATH:	${SRCDIR} ${SRCDIR}/../tcpdump

.include "../../Makefile.inc"
