SRCDIR=	${.CURDIR}/../../kame/pma

PROG=	pma
SRCS=	main.c pma.y.c pma.l.c error.c misc.c show.c yylex.c
CLEANFILES+= pma.y.c pma.l.c pma.y.h y.output y.tab.c y.tab.h

CFLAGS+= -DYYDEBUG -DPM -DPM_USE_SOCKET -DKAME -I$(SRCDIR) -I$(.OBJDIR)

LDADD+=	-lkvm -ly -ll
DPADD+=	${LIBKVM} ${LIBY} ${LIBL}

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

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
