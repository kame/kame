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

CC	=	gcc
CCLD	?=	gcc
CFLAGS	+=	-DINET6 -DIPSEC # -DRADISH
INCL	+=	#-I/usr/src/sys
LIBS	+=	-L${.CURDIR}/../libinet6/obj -L${.CURDIR}/../libinet6 \
		-L/usr/local/v6/lib -linet6

COPY	?=	-c
STRIP	?=	-s

BINGRP	?=	bin
BINOWN	?=	bin
BINMODE	?=	555

MANGRP	?=	bin
MANOWN	?=	bin
MANMODE	?=	444

RM	?=	/bin/rm -f
INSTALL	?=	/usr/bin/install

PREFIX	?=	/usr/local/v6/
DESTDIR	?=	bin
MANDIR	=	/usr/local/v6/man/man

.if defined(PROG)
all	:	${PROG}

${PROG}	:	${OBJS}
	${CCLD} -o $@ ${OBJS} ${LIBS}

install	:	${PROG}
	${INSTALL} ${COPY} ${STRIP} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
	${INSTALLFLAGS} ${PROG} ${PREFIX}${DESTDIR}
.if !defined(NOMAN)
.for sect in 1 2 3 4 5 6 7 8 9 n
.if defined(MAN${sect})
.for page in ${MAN${sect}}
	${INSTALL} ${COPY} -o ${MANOWN} -g ${MANGRP} -m ${MANMODE} \
		${page} ${MANDIR}${sect}
.endfor
.endif
.endfor
.endif

clean	::
	${RM} ${PROG} a.out core *~ *.o

.c.o	:
	${CC} ${CDEBUG} ${CFLAGS} ${INCL} -c $*.c
.endif
