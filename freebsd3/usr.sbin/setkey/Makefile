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
CFLAGS+=-I${.OBJDIR} -I${SRCDIR} -I${.OBJDIR}/../../lib/libipsec
LDADD+= -L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
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
