SRCDIR=	${.CURDIR}/../../kame/setkey

PROG=	setkey
SRCS=	setkey.c parse.y token.l
CFLAGS+=-g
LDADD+=	-ll -ly
DPADD+=	${LIBL} ${LIBY}
CLEANFILES+=	y.tab.c y.tab.h key_test.o keytest
YFLAGS+=-d

SCRIPTS=	scriptdump

BINOWN=root
BINGRP=bin
BINMODE=555

all: ${PROG} scriptdump

CFLAGS+=-DIPSEC_DEBUG -DINET6 -DYY_NO_UNPUT
CFLAGS+=-I${.CURDIR} -I${SRCDIR}
LDADD+= -L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libipsec/obj \
	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.CURDIR}/../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
CLEANFILES+=	scriptdump

MAN8=	setkey.8
LOCALPREFIX=	/usr/local

# FreeBSD special
SRCS+=y.tab.h
y.tab.h: parse.y

scriptdump: scriptdump.pl
	sed -e 's#@LOCALPREFIX@#${LOCALPREFIX}#' < $> > scriptdump

.PATH:	${SRCDIR}

.include <bsd.prog.mk>

CLEANFILES+=	y.tab.h
