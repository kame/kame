SRCDIR=	${.CURDIR}/../../../kame/racoon

CFLAGS=	-g -O2
OPTFLAG+=-DHAVE_PFKEYV2 -DYIPS_DEBUG
CPPFLAGS+=-DINET6 -DHAVE_FUNCTION_MACRO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBL=1 -DHAVE_LIBY=1 -DENABLE_IPV6=1 -DADVAPI=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_VARARGS_H=1 -DTIME_WITH_SYS_TIME=1 -DRETSIGTYPE=void -DHAVE_VPRINTF=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 -DHAVE_STRERROR=1 -DHAVE_STRTOL=1 -DHAVE_STRTOUL=1 -DHAVE_STRDUP=1  $(OPTFLAG) -DIPSEC -I. -I$(SRCDIR) -Dss_family=__ss_family -Dss_len=__ss_len -DSYSCONFDIR=\"$(ETCDIR)\" -DINCLUDE_PATH_OPENSSL=1
CPPFLAGS+=-DYY_NO_UNPUT
.if exists(/usr/local/ssl/include/openssl/des.h)
CPPFLAGS+=-I/usr/local/ssl/include
.elif exists(/usr/pkg/include/openssl/des.h)
CPPFLAGS+=-I/usr/pkg/include
.endif
YFLAGS+=-d

.if exists(/usr/local/ssl/include/openssl/rc5.h) || exists(/usr/pkg/include/openssl/rc5.h)
CPPFLAGS+=-DHAVE_OPENSSL_RC5_H=1
.else
CPPFLAGS+=-DNO_RC5=1
.endif
.if exists(/usr/local/ssl/include/openssl/idea.h) || exists(/usr/pkg/include/openssl/idea.h)
CPPFLAGS+=-DHAVE_OPENSSL_IDEA_H=1
.else
CPPFLAGS+=-DNO_IDEA=1
.endif
.if exists(/usr/local/ssl/include/poenssl/cversion.h) || exists(/usr/pkg/include/openssl/cversion.h)
CPPFLAGS+=-DHAVE_OPENSSL_CVERSION_H=1
.endif
.if exists(/usr/pkg/include/ssleay/opensslv.h) || exists(/usr/pkg/include/openssl/opensslv.h) || exists(/usr/local/ssl/include/openssl/opensslv.h)
CPPFLAGS+=-DHAVE_OPENSSL_OPENSSLV_H=1
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

.if exists(/usr/local/ssl/lib/libcrypto.a)
LDADD+=	-L/usr/local/ssl/lib -lcrypto
.elif exists(/usr/pkg/lib/libcrypto.a) || exists(/usr/pkg/lib/libcrypto.so.1.0)
LDADD+=	-L/usr/pkg/lib -lcrypto
.endif

.PATH:	${SRCDIR} ${SRCDIR}/../tcpdump

.include "../../Makefile.inc"
