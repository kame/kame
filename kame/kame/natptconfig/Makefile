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

.PATH:		${.CURDIR}/../../../sys/netinet6

BINDIR=	${PREFIX}/sbin
PROG=	natptconfig
SRCS=	main.c natptconfig.y.c natptconfig.l.c misc.c show.c yylex.c
CLEANFILES+= natptconfig.y.c natptconfig.l.c natptconfig.y.h y.output y.tab.c y.tab.h

.if (${OPSYS} != "NetBSD")
CFLAGS+= -Wall
.endif

CFLAGS+= -g -DYYDEBUG -DNATPT -DreadKMEM

LDADD+=	-L${.CURDIR}/../libinet6 -L${.CURDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lkvm -ly -ll
DPADD+=	${.CURDIR}/../libinet6/libinet6.a \
	${.CURDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.if (${OPSYS} != "NetBSD")
MAN8=	natptconfig.8
.else
MAN=	natptconfig.8
.endif


natptconfig.y.c \
natptconfig.y.h:	natptconfig.y showvar.h
		$(YACC) ${YFLAGS} natptconfig.y
		mv y.tab.c natptconfig.y.c
		mv y.tab.h natptconfig.y.h

natptconfig.l.c:	natptconfig.l
		$(LEX) -t -L natptconfig.l > natptconfig.l.c


.include <bsd.prog.mk>
