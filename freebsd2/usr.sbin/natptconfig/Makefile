SRCDIR	= ${.CURDIR}/../../kame/natptconfig

PROG=	natptconfig
SRCS=	main.c cfparse.y cftoken.l misc.c show.c yylex.c showsubs.c

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

cfparse.h:	cfparse.y

main.o:	cfparse.h
misc.o:	cfparse.h
yylex.o:	cfparse.h

.include <bsd.prog.mk>
