SRCDIR=	${.CURDIR}/../../kame/rrenumd

PROG=	rrenumd
SRCS=	rrenumd.c  parser.y lexer.l
YFLAGS+=	-d

CPPFLAGS+= -DINET6 -I${SRCDIR} -I${.CURDIR}
LDADD+=	-L${.CURDIR}/../../lib/libipsec -L${.CURDIR}/../../lib/libipsec/obj \
	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-lcompat
DPADD+=	${LIBCOMPAT}
LDADD+= -ll -ly
DPADD+=	${LIBL} ${LIBY}

MAN=	rrenumd.8 rrenumd.conf.5

.if defined(YACCDEBUG)
CFLAGS+= -DYYDEBUG
YFLAGS+= -t -v
.endif

.PATH:	${SRCDIR}

.include <bsd.prog.mk>

CLEANFILES+=	y.tab.h
