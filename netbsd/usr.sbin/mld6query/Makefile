BINDIR=	$(PREFIX)/sbin
PROG=	mld6query
SRCS=	mld6.c

MAN=	mld6query.8

BINOWN=	root
BINGRP=	bin

CPPFLAGS+= -DINET6 -DIPSEC -DUSE_RFC2292BIS

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a

.PATH:	${.CURDIR}/../../kame/mld6query

.include <bsd.prog.mk>
