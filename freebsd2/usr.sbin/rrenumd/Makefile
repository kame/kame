SRCDIR=	${.CURDIR}/../../kame/rrenumd

PROG=	rrenumd
SRCS=	rrenumd.c  parser.y lexer.l
YFLAGS+=	-d

CFLAGS+= -DINET6 -DIPSEC -I${SRCDIR} -I${.CURDIR}
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lcompat
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libipsec/obj \
	-L/usr/local/v6/lib -lipsec
DPADD+=	${.CURDIR}/../../lib/libipsec/libipsec.a \
	${.CURDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
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
