#	$KAME: Makefile,v 1.5 2001/09/02 19:32:27 fujisawa Exp $

# Copyright (C) 1995, 1996, 1997, 1998, 1999, 2000 and 2001 WIDE Project.
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

BINDIR=	${PREFIX}/sbin
PROG=	natptconfig
LDADD+=-ly -ll
SRCS = main.c misc.c show.c showsubs.c yylex.c
SRCS+= cfparse.y cftoken.l
YACC= yacc -tv

.if (${OPSYS} == "NetBSD")
YFLAGS+=-d
.endif

CC=gcc
.if (${OPSYS} != "NetBSD")
CFLAGS+=-g -Wall -DYYDEBUG
.else
CPPFLAGS+=-g
.endif
.if (${OPSYS} != "NetBSD")
MAN1=
MAN8=	natptconfig.8
.else
MAN=	natptconfig.8
.endif

.if exists(/usr/local/v6/lib/libinet6.a)
LDADD+=	-L${.OBJDIR}/../libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lkvm
DPADD+= ${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
.endif

tag:
	etags *.[chly] /usr/include/netinet6/natpt_*.h

clean:
	-rm -f $(PROG) *.o *.core
	-rm -f cfparse.[ch] cfparse.output cftoken.c
	-rm -f natptconfig.8.gz

.include <bsd.prog.mk>
