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
PROG=	ptrconfig
SRCS=	main.c ptrconfig.y.c ptrconfig.l.c error.c misc.c show.c yylex.c
CLEANFILES+= ptrconfig.y.c ptrconfig.l.c ptrconfig.y.h y.output y.tab.c y.tab.h

.if (${OPSYS} != "NetBSD")
CFLAGS+= -Wall
.endif

CFLAGS+= -DYYDEBUG -DPTR -DreadKMEM

LDADD+=	-L${.CURDIR}/../libinet6 -L${.CURDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lkvm -ly -ll
DPADD+=	${.CURDIR}/../libinet6/libinet6.a \
	${.CURDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

#.if (${OPSYS} != "NetBSD")
#MAN8=	ptrconfig.8 ptrlog.8
#.else
#MAN=	ptrconfig.8 ptrlog.8
#.endif

NOMAN=yes

.include <bsd.prog.mk>


#
#
#

               MV = /bin/mv

ptrconfig.y.c \
ptrconfig.y.h:	ptrconfig.y showvar.h
		$(YACC) -d ptrconfig.y
		$(MV) y.tab.c ptrconfig.y.c
		$(MV) y.tab.h ptrconfig.y.h

ptrconfig.l.c:	ptrconfig.l
		$(LEX) -t -L ptrconfig.l > ptrconfig.l.c
