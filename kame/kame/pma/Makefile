# Copyright (c) 1996 WIDE Project. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted provided that the above copyright notice
# and this paragraph are duplicated in all such forms and that any
# documentation, advertising materials, and other materials related to
# such distribution and use acknowledge that the software was developed
# by the WIDE Project, Japan. The name of the Project may not be used to
# endorse or promote products derived from this software without
# specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS IS''
# AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
# LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE.

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	${PREFIX}/bin
PROG=	pma
SRCS=	main.c pma.y.c pma.l.c error.c misc.c show.c yylex.c
CLEANFILES+= pma.y.c pma.l.c pma.y.h y.output y.tab.c y.tab.h

.if (${OPSYS} != "NetBSD")
CFLAGS+= -Wall
.endif

CFLAGS+= -DYYDEBUG -DPM -DPM_USE_SOCKET -DKAME -I$(.CURDIR) -I$(.OBJDIR)

LDADD+=	-lkvm -ly -ll

.if (${OPSYS} != "NetBSD")
MAN8=	pma.8 pmlog.8
.else
MAN=	pma.8 pmlog.8
.endif

.include <bsd.prog.mk>


#
#
#

               MV = /bin/mv

pma.y.c \
pma.y.h:	pma.y showvar.h
		$(YACC) -d $(.CURDIR)/pma.y
		$(MV) y.tab.c pma.y.c
		$(MV) y.tab.h pma.y.h

pma.l.c:	pma.l
		$(LEX) -t -L $(.CURDIR)/pma.l > pma.l.c
