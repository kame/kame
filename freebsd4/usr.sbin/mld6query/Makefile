PROG=	mld6query
SRCS=	mld6.c

MAN8=	mld6query.8

BINOWN=	root
BINGRP=	bin

CFLAGS+= -DINET6 -DIPSEC -DUSE_RFC2292BIS

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/mld6query

.include <bsd.prog.mk>
