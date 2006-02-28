PROG=	ping6
MAN8=	ping6.8
SRCS=	ping6.c md5.c

CFLAGS+=-DINET6 -DIPSEC
CFLAGS+=-I${.CURDIR}/../../kame/ping6

BINOWN=	root
BINGRP=	bin
BINMODE=4555

LDADD+=	-L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6 -lm
DPADD+= ${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/ping6

# kame scopeid hack
CFLAGS+=-DKAME_SCOPEID

# new advanced API
CFLAGS+=-DUSE_RFC3542

.include <bsd.prog.mk>
