SRCDIR	= ${.CURDIR}/../../kame/natptconfig

PROG=	natptconfig
SRCS=	main.c natptconfig.y.c natptconfig.l.c misc.c show.c yylex.c

MAN8=	natptconfig.8

CFLAGS+=	-g -I${.OBJDIR} -DYYDEBUG -DreadKMEM
CLEANFILES+=	natptconfig.y.c natptconfig.y.h natptconfig.l.c

LDADD+=	-lutil
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lkvm -ly -ll
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}


natptconfig.y.c \
natptconfig.y.h:	natptconfig.y showvar.h
		${YACC} ${YFLAGS} ${SRCDIR}/natptconfig.y
		mv y.tab.c natptconfig.y.c
		mv y.tab.h natptconfig.y.h

natptconfig.l.c:	natptconfig.l
		${LEX} -t -L ${SRCDIR}/natptconfig.l > natptconfig.l.c

main.o:	natptconfig.y.h
misc.o:	natptconfig.y.h
yylex.o:	natptconfig.y.h

.include <bsd.prog.mk>
