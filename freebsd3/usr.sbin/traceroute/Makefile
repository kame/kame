SRCDIR=	${.CURDIR}/../../kame/traceroute

PROG=	traceroute
SRCS=	traceroute.c ifaddrlist.c savestr.c version.c

BINOWN=	root
BINGRP=	bin
BINMODE=4555

DEFS =  -DHAVE_MALLOC_H=1 -DHAVE_SYS_SELECT_H=1 -DHAVE_SYS_SOCKIO_H=1 -DHAVE_STRERROR=1 -DHAVE_SETLINEBUF=1 -DHAVE_SOCKADDR_SA_LEN=1  -DIPSEC
CFLAGS+=-I${SRCDIR} -O2
CFLAGS+=${DEFS}
# workaround for gnuc.h - should be revisited
CFLAGS+=-I${SRCDIR}/lbl

LDADD+= -L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN8=	traceroute.8

version.c: VERSION
	@rm -f $@
	sed -e 's/.*/char version[] = "&";/' $> > $@

.PATH: ${SRCDIR}

.include <bsd.prog.mk>

CLEANFILES+=	version.c
