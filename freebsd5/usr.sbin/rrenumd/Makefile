SRCDIR=	${.CURDIR}/../../kame/rrenumd

PROG=	rrenumd
SRCS=	rrenumd.c  parser.y lexer.l
YFLAGS+=	-d

CFLAGS+= -DINET6 -DIPSEC -I${SRCDIR} -I${.OBJDIR}
LDADD+=	-L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+= -ll -ly
DPADD+=	${LIBL} ${LIBY}

MAN5=	rrenumd.conf.5
MAN8=	rrenumd.8

# FreeBSD special
SRCS+=y.tab.h
y.tab.h: parser.y

.if defined(YACCDEBUG)
CFLAGS+= -DYYDEBUG
YFLAGS+= -t -v
.endif

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
