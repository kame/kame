#SRCDIR=	${.CURDIR}/../../../kame/racoon


#CC=	gcc
#LDFLAGS=
#CPPFLAGS=	
#OPTFLAG=-DHAVE_PFKEYV2 -DYIPS_DEBUG -Wall -O
#CFLAGS=	-DINET6 -I/usr/pkg/include/ssleay -g -O2  -DHAVE_PRINT_ISAKMP_C=1 -DHAVE_FUNCTION_MACRO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBL=1 -DHAVE_LIBY=1 -DINET6=1 -DADVAPI=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_VARARGS_H=1 -DTIME_WITH_SYS_TIME=1 -DRETSIGTYPE=void -DHAVE_VPRINTF=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 -DHAVE_STRERROR=1 -DHAVE_STRTOL=1 -DHAVE_STRTOUL=1 -DHAVE_STRDUP=1  $(CPPFLAGS) $(OPTFLAG) -DIPSEC -I. -I$(srcdir) -Dss_family=__ss_family -Dss_len=__ss_len
#YFLAGS+=-d

PROG=	racoon
#kmpstat eaytest
#PROG+=	pfkey
SRCS=	handler.c isakmp.c isakmp_inf.c ipsec_doi.c pfkey.c main.c \
	post_com.c schedule.c session.c crypto.c cfparse.c cftoken.c \
	admin.c misc.c vmbuf.c \
	print-isakmp.c

all: $(PROG)

MAN=	racoon.8

.include <bsd.prog.mk>

CLEANFILES+=	y.tab.h cfparse.c cftoken.c
