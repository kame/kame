SRCDIR=	${.CURDIR}/../../kame/pma

PROG=	pma
SRCS=	main.c pma.y.c pma.l.c error.c misc.c show.c yylex.c
CLEANFILES+= pma.y.c pma.l.c pma.y.h y.output y.tab.c y.tab.h

CFLAGS+= -DYYDEBUG -DPM -DPM_USE_SOCKET -DKAME -I$(SRCDIR) -I$(.OBJDIR)
LDADD+=	-lkvm -ly -ll

MAN8=	pma.8 pmlog.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>


#
#
#

               MV = /bin/mv

pma.y.c \
pma.y.h:	pma.y showvar.h
		$(YACC) -d $(SRCDIR)/pma.y
		$(MV) y.tab.c pma.y.c
		$(MV) y.tab.h pma.y.h

pma.l.c:	pma.l
		$(LEX) -t -L $(SRCDIR)/pma.l > pma.l.c
