SRCDIR=	${.CURDIR}/../../kame/pma

PROG=	pma
SRCS=	main.c pma.y.c pma.l.c error.c misc.c show.c yylex.c
CLEANFILES+= pma.y.c pma.l.c pma.y.h y.output y.tab.c y.tab.h

CFLAGS+= -DYYDEBUG -DPM -DPM_USE_SOCKET -DKAME -I$(.CURDIR) -I$(.OBJDIR)
LDADD+=	-lkvm -ly -ll

MAN8=	pma.8 pmlog.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>