SRCDIR=	${.CURDIR}/../../kame/natptconfig

PROG=	natptconfig
SRCS=	main.c cfparse.y cftoken.l misc.c show.c yylex.c showsubs.c

MAN=	natptconfig.8

CPPFLAGS+=	-I. -I${.CURDIR} -DYYDEBUG -DreadKMEM
CFLAGS+=	-g -Wall
CLEANFILES+=	natptconfig.y.c natptconfig.y.h natptconfig.l.c

LDADD+=	-lutil
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lkvm -ly -ll
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

YFLAGS+=	-d

y.tab.h:	cfparse.y
cfparse.h:	y.tab.h
	cp y.tab.h cfparse.h

main.o: cfparse.h
show.o: cfparse.h
showsubs.o: cfparse.h

CLEANFILES+=	cfparse.h y.tab.h

.include <bsd.prog.mk>
