SRCDIR=	${.CURDIR}/../../kame/icmp6dump

PROG=	icmp6dump

BINOWN=	root
BINGRP=	bin
BINMODE=4555
CFLAGS+=-g
CPPFLAGS+=-DINET6

LDADD+=	-L${.OBJDIR}/../libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN=	icmp6dump.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
