SRCDIR=	${.CURDIR}/../../../kame/racoon

CFLAGS+=-g -O2
OPTFLAG+=-DHAVE_PFKEYV2 -DYIPS_DEBUG
CFLAGS+=-DINET6 -DHAVE_FUNCTION_MACRO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBL=1 -DHAVE_LIBY=1 -DENABLE_IPV6=1 -DADVAPI=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_VARARGS_H=1 -DTIME_WITH_SYS_TIME=1 -DRETSIGTYPE=void -DHAVE_VPRINTF=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 -DHAVE_STRERROR=1 -DHAVE_STRTOL=1 -DHAVE_STRTOUL=1 -DHAVE_STRDUP=1  $(OPTFLAG) -DIPSEC -I$(SRCDIR) -I. -Dss_family=__ss_family -Dss_len=__ss_len -DSYSCONFDIR=\"$(ETCDIR)\" -DHAVE_SIGNING_C
CFLAGS+=-DYY_NO_UNPUT
CFLAGS+=-I${.CURDIR}/../../../kame/libipsec
YFLAGS+=-d

CFLAGS+=-DHAVE_OPENSSL_PEM_H=1
CFLAGS+=-DHAVE_OPENSSL_X509_H=1
CFLAGS+=-DHAVE_OPENSSL_OPENSSLV_H=1

LDADD+=	-ly -ll
DPADD+=	${LIBY} ${LIBL}
LDADD+=	-L${.OBJDIR}/../../../lib/libipsec \
	-L${.OBJDIR}/../../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	-L${.OBJDIR}/../../../lib/libinet6/libinet6.a \
	-L/usr/local/v6/lib/libinet6.a
LDADD+= -L/usr/lib -lcrypto
DPADD+= /usr/lib/libcrypto.a
# for USA resident
.if exists(/usr/local/lib/libRSAglue.a) && exists(/usr/local/lib/librsaref.a)
LDADD+=	-L/usr/local/lib -lRSAglue -lrsaref
DPADD+=	/usr/local/lib/libRSAglue.a /usr/local/lib/librsaref.a
.elif exists(/usr/lib/libRSAglue.a) && exists(/usr/local/lib/librsaref.a)
LDADD+=	-lRSAglue -L/usr/local/lib -lrsaref
DPADD+=	/usr/lib/libRSAglue.a /usr/local/lib/librsaref.a
.endif

.PATH:	${SRCDIR} ${SRCDIR}/../tcpdump

.include "../../Makefile.inc"
