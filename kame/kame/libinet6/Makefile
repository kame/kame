# Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

LIB=	inet6
#CFLAGS+=-g
.if (${OPSYS} != "NetBSD")
CFLAGS+=-DDNS
CFLAGS+=-DINET6 -DUSE_GETIPNODEBY
.else
CPPFLAGS+=-DDNS
CPPFLAGS+=-DINET6 -DUSE_GETIPNODEBY
.endif
.if (${OPSYS} != "NetBSD")
CFLAGS+=-Wall
.endif

SRCS=	getaddrinfo.c getnameinfo.c ifname.c vars.c rresvport_af.c rcmd.c
SRCS+=	rthdr.c ip6opt.c
SRCS+=	name6.c
SRCS+=	base64.c herror.c nsap_addr.c 
SRCS+=	res_comp.c res_data.c res_debug.c
SRCS+=	res_init.c res_mkquery.c res_query.c 
SRCS+=	res_send.c

.if (${OPSYS} != "NetBSD")
MAN3=	getaddrinfo.3 getnameinfo.3 gethostbyname.3 resolver.3 \
	rresvport_af.3 if_indextoname.3 getipnodebyname.3
.else
MAN=	getaddrinfo.3 getnameinfo.3 gethostbyname.3 resolver.3 \
	rresvport_af.3 if_indextoname.3 getipnodebyname.3
.endif
.if (${OPSYS} != "BSD/OS")
MLINKS+=	getipnodebyname.3 getipnodebyaddr.3 \
		getipnodebyname.3 freehostent.3 \
		getaddrinfo.3 freeaddrinfo.3 \
		getaddrinfo.3 gai_strerror.3 \
		if_indextoname.3 if_nametoindex.3 \
		if_indextoname.3 if_nameindex.3 \
		if_indextoname.3 if_freenameindex.3
.else
afterinstall:
	/bin/rm -f  $(MANDIR)3/getipnodebyaddr.3
	/bin/rm -f  $(MANDIR)3/freehostent.3
	ln $(MANDIR)3/getipnodebyname.3 $(MANDIR)3/getipnodebyaddr.3
	ln $(MANDIR)3/getipnodebyname.3 $(MANDIR)3/freehostent.3
	/bin/rm -f  $(MANDIR)3/freeaddrinfo.3
	/bin/rm -f  $(MANDIR)3/gai_strerror.3
	ln $(MANDIR)3/getaddrinfo.3 $(MANDIR)3/freeaddrinfo.3
	ln $(MANDIR)3/getaddrinfo.3 $(MANDIR)3/gai_strerror.3
	/bin/rm -f  $(MANDIR)3/if_nametoindex.3
	/bin/rm -f  $(MANDIR)3/if_nameindex.3
	/bin/rm -f  $(MANDIR)3/if_freenameindex.3
	ln $(MANDIR)3/if_indextoname.3 $(MANDIR)3/if_nametoindex.3
	ln $(MANDIR)3/if_indextoname.3 $(MANDIR)3/if_nameindex.3
	ln $(MANDIR)3/if_indextoname.3 $(MANDIR)3/if_freenameindex.3
.endif

.PATH:	${.CURDIR}/resolv

# If you attempt to build shared library, enable the following lines.
# Do it at your own risk!  libinet6 is updated frequently so version
# management would be very hard...
#SHLIB_MAJOR=	1
#SHLIB_MINOR=	0

.if (${OPSYS} == "NetBSD")
MKPIC=no
.endif

.include <bsd.lib.mk>
