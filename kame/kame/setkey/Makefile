# Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	$(PREFIX)/sbin
PROG=	setkey
SRCS=	setkey.c parse.y token.l
CFLAGS+=-g
LDADD+=	-ll -ly
CLEANFILES+=	y.tab.c y.tab.h key_test.o keytest
YFLAGS+=-d

SCRIPTS=	scriptdump

BINOWN  = root
BINGRP  = bin
BINMODE = 555

all: ${PROG} scriptdump

#CFLAGS+=	-Wall
.if (${OPSYS} != "BSD/OS")
CFLAGS+=	-Werror
.endif
.if (${OPSYS} == "FreeBSD")
SRCS+=y.tab.h
y.tab.h: parse.y
.endif
.if (${OPSYS} == "NetBSD")
CPPFLAGS+=-DIPSEC_DEBUG -DINET6 -DYY_NO_UNPUT
CPPFLAGS+=-I${.CURDIR}/../libipsec -I${.OBJDIR}
.else
CFLAGS+=-DIPSEC_DEBUG -DINET6 -DYY_NO_UNPUT
CFLAGS+=-I${.CURDIR}/../libipsec -I${.OBJDIR}
.endif
LDADD+= -L${.OBJDIR}/../libipsec -L${.OBJDIR}/../libipsec/obj \
	-L/usr/local/v6/lib -lipsec
DPADD+=	${.OBJDIR}/../libipsec/libipsec.a \
	${.OBJDIR}/../libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+=	-L${.OBJDIR}/../libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
CLEANFILES+=	scriptdump

.if (${OPSYS} != "NetBSD")
MAN8=	setkey.8
LOCALPREFIX=	/usr/local
.else
MAN=	setkey.8
LOCALPREFIX=	/usr/pkg
.endif

scriptdump: scriptdump.pl
	sed -e 's#@LOCALPREFIX@#${LOCALPREFIX}#' < ${.CURDIR}/scriptdump.pl > scriptdump

.include <bsd.prog.mk>
