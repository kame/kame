SRCDIR=	${.CURDIR}/../../kame/traceroute

PROG=	traceroute
SRCS=	traceroute.c ifaddrlist.c savestr.c version.c

BINOWN=	root
BINGRP=	bin
BINMODE=4555

DEFS =  -DHAVE_MALLOC_H=1 -DHAVE_SYS_SELECT_H=1 -DHAVE_SYS_SOCKIO_H=1 -DHAVE_STRERROR=1 -DHAVE_SETLINEBUF=1 -DHAVE_RAW_OPTIONS=1 -DHAVE_SOCKADDR_SA_LEN=1 -DHAVE_UDPIPHDR_NEXT=1  -DIPSEC -DHAVE_GETIFADDRS -DHAVE_IFADDRS_H -DHAVE_FREEIFADDRS
CFLAGS+=-I${SRCDIR} -O2
CFLAGS+=${DEFS}
# workaround for gnuc.h - should be revisited
CFLAGS+=-I${SRCDIR}/lbl

LDADD+= -L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libipsec/obj \
	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.CURDIR}/../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN8=	traceroute.8

version.c: VERSION
	@rm -f $@
	sed -e 's/.*/char version[] = "&";/' $> > $@

.PATH: ${SRCDIR}

.include <bsd.prog.mk>

CLEANFILES+=	version.c
