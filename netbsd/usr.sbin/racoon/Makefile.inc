SRCDIR=	${.CURDIR}/../../../kame/racoon

CFLAGS=	-g -O2
OPTFLAG+=-DHAVE_PFKEYV2 -DYIPS_DEBUG
CPPFLAGS+=-DINET6 -I/usr/pkg/include/ssleay -DHAVE_FUNCTION_MACRO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBL=1 -DHAVE_LIBY=1 -DINET6=1 -DADVAPI=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_VARARGS_H=1 -DTIME_WITH_SYS_TIME=1 -DRETSIGTYPE=void -DHAVE_VPRINTF=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 -DHAVE_STRERROR=1 -DHAVE_STRTOL=1 -DHAVE_STRTOUL=1 -DHAVE_STRDUP=1  $(OPTFLAG) -DIPSEC -I. -I$(SRCDIR) -Dss_family=__ss_family -Dss_len=__ss_len
YFLAGS+=-d

.if exists(/usr/pkg/include/ssleay/idea.h)
CPPFLAGS+=-DHAVE_IDEA_H=1
.endif

LDADD+=	-ly -ll -L/usr/pkg/lib -lcrypto
LDADD+=	-L${.CURDIR}/../../lib/libipsec \
	-L${.CURDIR}/../../lib/libipsec/obj \
	-L/usr/local/v6/lib -lipsec
DPADD+=	${.CURDIR}/../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	-L${.CURDIR}/../../lib/libinet6/libinet6.a \
	-L${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	-L/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR} ${SRCDIR}/../tcpdump

.include "../../Makefile.inc"
