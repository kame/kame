SRCDIR=	${.CURDIR}/../../kame/natptconfig

PROG=	natptconfig
SRCS=	main.c cftoken.l cfparse.y misc.c show.c yylex.c showsubs.c

MAN5=	natpt.conf.5
MAN8=	natptconfig.8

CFLAGS+= -g -I${.OBJDIR} -DYYDEBUG -Wall -DreadKMEM

LDADD+=	-lutil
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6 -lkvm -ly -ll
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
