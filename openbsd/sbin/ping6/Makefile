PROG=	ping6
MAN=	ping6.8

CPPFLAGS+= -DINET6

BINOWN=	root
BINGRP=	bin
BINMODE=4555

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/ping6

# kame scopeid hack
CPPFLAGS+=-DKAME_SCOPEID

# new advanced API
CPPFLAGS+=-DUSE_RFC2292BIS

.include <bsd.prog.mk>
