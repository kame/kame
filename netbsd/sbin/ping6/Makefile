PROG=	ping6
MAN=	ping6.8

CPPFLAGS+= -DINET6 -DIPSEC

BINOWN=	root
BINGRP=	bin
BINMODE=4555

LDADD+=	-L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libipsec/obj \
	-L/usr/local/v6/lib -lipsec
DPADD+= ${.CURDIR}/../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/ping6

.include <bsd.prog.mk>
