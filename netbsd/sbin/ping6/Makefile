PROG=	ping6
MAN=	ping6.8

CPPFLAGS+=-DINET6 -DIPSEC
#CFLAGS+=-Wall -Werror -Dlint -g

BINOWN=	root
BINGRP=	bin
BINMODE=4555

LDADD+=	-L${.CURDIR}/../../lib/libipsec \
	-L${.CURDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+= ${.CURDIR}/../../lib/libipsec/libipsec.a
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a
LDADD+=	-lm
DPADD+=	${LIBM}

.PATH:	${.CURDIR}/../../kame/ping6

# kame scopeid hack
CPPFLAGS+=-DKAME_SCOPEID

# new advanced API
CPPFLAGS+=-DUSE_RFC2292BIS

CPPFLAGS+=-DHAVE_POLL_H

.include <bsd.prog.mk>
