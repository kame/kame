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

#	$Id: Makefile,v 1.1.1.1 1999/12/06 06:26:33 jinmei Exp $

.ifndef PREFIX
PREFIX=/usr/local/v6
.endif

SBINDIR=${PREFIX}/sbin
ETCDIR=	${PREFIX}/etc
RCDIR=	${ETCDIR}/rc.d
MANDIR= ${PREFIX}/man
MAN8=   ${MANDIR}/man8
MANMODE=0644
#PROG=	mpsend mprecv
CFLAGS+=-Wall
SENDSRC= mpsend.c
SENDOBJ= mpsend.o
SENDLIB=
RECVSRC= mprecv.c
RECVOBJ= mprecv.o
RECVLIB= -lm

CC=	gcc
CPPFLAGS+=-DINET6
CFLAGS+=-g

LDADD+=	-L/usr/local/v6/lib -linet6

MAN=	mpsend.8 mprecv.8
BINMODE=0755
BINOWN=root
BINGRP=wheel

INSTALLFLAGS=-c

all: mpsend mprecv

mpsend: $@.o mping.h
	${CC} -o $@ ${SENDOBJ} ${LDFLAGS} ${LDADD} ${SENDLIB}
	
mprecv: $@.o mping.h
	${CC} -o $@ ${RECVOBJ} ${LDFLAGS} ${LDADD} ${RECVLIB}

install: all
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${INSTALLFLAGS} ${.CURDIR}/mpsend ${SBINDIR}
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${INSTALLFLAGS} ${.CURDIR}/mprecv ${SBINDIR}
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${MANMODE} \
		${INSTALLFLAGS} ${.CURDIR}/mpsend.8 ${MAN8}
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${MANMODE} \
		${INSTALLFLAGS} ${.CURDIR}/mprecv.8 ${MAN8}
	if [ -d ${RCDIR} ]; then \
		install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
			${INSTALLFLAGS} ${.CURDIR}/mpsend.sh.sample ${RCDIR}; \
		install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
			${INSTALLFLAGS} ${.CURDIR}/mprecv.sh.sample ${RCDIR}; \
	else \
		install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
			${INSTALLFLAGS} ${.CURDIR}/mpsend.sh.sample ${ETCDIR};\
		install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
			${INSTALLFLAGS} ${.CURDIR}/mprecv.sh.sample ${ETCDIR};\
	fi

tar:
	tar cf mping.tar *.c *.h *.8 *.sample Makefile
