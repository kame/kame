# Copyright (c) 1999 WIDE Project. All rights reserved.
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

SRCDIR=	${.CURDIR}/../../../kame/pim6sd

PROG=	pim6sd
SRCS=	mld6.c mld6_proto.c\
	inet6.c kern.c main.c config.c debug.c routesock.c vers.c callout.c\
	route.c vif.c timer.c mrt.c pim6.c pim6_proto.c rp.c crc.c trace.c\
	cfparse.y cftoken.l
CLEANFILES+= lex.yy.c y.tab.h y.tab.c
CFLAGS+= -g
CFLAGS+=-I.
CFLAGS+=-DINET6 -DPIM -DIOCTL_OK_ON_RAW_SOCKET -I${SRCDIR}
CFLAGS+=-DHAVE_STDARG_H
LDADD+=	-L${.OBJDIR}/../../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN5=	pim6sd.conf.5
MAN8=	pim6sd.8

# FreeBSD special
SRCS+=y.tab.h

afterinstall:
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${INSTALLFLAGS} ${SRCDIR}/pim6stat ${DESTDIR}${BINDIR}

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
