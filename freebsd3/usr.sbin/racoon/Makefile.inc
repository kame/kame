SRCDIR=	${.CURDIR}/../../../kame/racoon

CFLAGS+=-g -O2
OPTFLAG+=-DHAVE_PFKEYV2 -DYIPS_DEBUG
CFLAGS+=-DINET6 -DHAVE_FUNCTION_MACRO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBL=1 -DHAVE_LIBY=1 -DENABLE_IPV6=1 -DADVAPI=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_VARARGS_H=1 -DTIME_WITH_SYS_TIME=1 -DRETSIGTYPE=void -DHAVE_VPRINTF=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 -DHAVE_STRERROR=1 -DHAVE_STRTOL=1 -DHAVE_STRTOUL=1 -DHAVE_STRDUP=1  $(OPTFLAG) -DIPSEC -I. -I$(SRCDIR) -Dss_family=__ss_family -Dss_len=__ss_len -DSYSCONFDIR=\"$(ETCDIR)\" -DINCLUDE_PATH_OPENSSL=1
CFLAGS+=-DYY_NO_UNPUT
YFLAGS+=-d

.if exists(/usr/local/include/openssl/rc5.h) || exists(/usr/local/ssl/include/openssl/rc5.h)
CFLAGS+=-DHAVE_OPENSSL_RC5_H=1
.else
CFLAGS+=-DNO_RC5=1
.endif
.if exists(/usr/local/include/openssl/idea.h) || exists(/usr/local/ssl/include/openssl/idea.h)
CFLAGS+=-DHAVE_OPENSSL_IDEA_H=1
.else
CFLAGS+=-DNO_IDEA=1
.endif
.if exists(/usr/local/include/openssl/cversion.h) || exists(/usr/local/ssl/include/openssl/cversion.h)
CFLAGS+=-DHAVE_OPENSSL_CVERSION_H=1
.endif
.if exists(/usr/local/openssl/include/opensslv.h) || exists(/usr/local/ssl/include/openssl/opensslv.h)
CFLAGS+=-DHAVE_OPENSSL_OPENSSLV_H=1
.endif
.if exists(/usr/local/include/openssl)
CFLAGS+=-I/usr/local/include
.elif exists(/usr/local/ssl/include/openssl)
CFLAGS+=-I/usr/local/ssl/include
.endif

LDADD+=	-ly -ll
DPADD+=	${LIBY} ${LIBL}
LDADD+=	-L${.OBJDIR}/../../../lib/libipsec -L${.OBJDIR}/../../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	-L${.OBJDIR}/../../../lib/libinet6/libinet6.a \
	-L/usr/local/v6/lib/libinet6.a
.if exists(/usr/local/lib/libcrypto.a)
LDADD+= -L/usr/local/lib -lcrypto
DPADD+= /usr/local/lib/libcrypto.a
.elif exists(/usr/local/ssl/lib/libcrypto.a)
LDADD+= -L/usr/local/ssl/lib -lcrypto
DPADD+= /usr/local/ssl/lib/libcrypto.a
.endif
# for USA resident
.if exists(/usr/local/lib/libRSAglue.a) && exists(/usr/local/lib/librsaref.a)
LDADD+=	-L/usr/local/lib -lRSAglue -lrsaref
DPADD+=	/usr/local/lib/libRSAglue.a /usr/local/lib/librsaref.a
.endif

.PATH:	${SRCDIR} ${SRCDIR}/../tcpdump

.include "../../Makefile.inc"
