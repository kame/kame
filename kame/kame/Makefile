# Copyright (c) 1996-1997 WIDE Project. All rights reserved.
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

.if exists(${.CURDIR}/Makefile.opsys)
.include "${.CURDIR}/Makefile.opsys"
.endif

# must build libinet6 and libipsec first!
SUBDIR=	libinet6 libipsec setkey
SUBDIR+=cksum6 gifconfig icmp6dump inet6d mld6query ping6 \
	prefix route6d ifmcstat rip6query rrenumd rtadvd rtsol rtsold faith faithd \
	traceroute6 pim6dd pim6sd send-pr mcastread mcastsend v6p mchat
SUBDIR+=	hroute6d
# pma: just for KAME/BSDI and KAME/FreeBSD
.if ${OPSYS} == "BSD/OS" || ${OPSYS} == "FreeBSD"
SUBDIR+=	pma
.endif

CONFIGURE_SUBDIR=	v6test bgpd libpcap tcpdump traceroute

all:
	for i in $(SUBDIR); do\
		(cd ${.CURDIR}/$$i; $(MAKE)); \
	done
	(cd ${.CURDIR}/v6test; \
		[ -f Makefile ] || ./configure; $(MAKE))
	(cd ${.CURDIR}/bgpd; \
		[ -f Makefile ] || \
		./configure --prefix=/usr/local/v6; \
		$(MAKE))
	(cd ${.CURDIR}/libpcap; \
		[ -f Makefile ] || \
		./configure --enable-ipv6 --prefix=/usr/local/v6; \
		$(MAKE))
	(cd ${.CURDIR}/tcpdump; \
		[ -f Makefile ] || \
		./configure --enable-ipv6 --prefix=/usr/local/v6; \
		$(MAKE))
	(cd ${.CURDIR}/traceroute; \
		[ -f Makefile ] || \
		./configure --prefix=/usr/local/v6; \
		$(MAKE))
	(cd ${.CURDIR}/dtcp; $(MAKE))
	(cd ${.CURDIR}/ndp; $(MAKE))
.if (${OPSYS} == "FreeBSD" || ${OPSYS} == "NetBSD")
	(cd ${.CURDIR}/man; $(MAKE))
.endif

install:
	for i in $(SUBDIR); do\
		(cd ${.CURDIR}/$$i; $(MAKE) install); \
	done
	(cd ${.CURDIR}/v6test; \
		[ -f Makefile ] || ./configure; $(MAKE) install)
	(cd ${.CURDIR}/bgpd; \
		[ -f Makefile ] || \
		./configure --prefix=/usr/local/v6; \
		$(MAKE) install)
	(cd ${.CURDIR}/libpcap; \
		[ -f Makefile ] || \
		./configure --enable-ipv6 --prefix=/usr/local/v6; \
		$(MAKE) install)
	(cd ${.CURDIR}/tcpdump; \
		[ -f Makefile ] || \
		./configure --enable-ipv6 --prefix=/usr/local/v6; \
		$(MAKE) install install-man)
	(cd ${.CURDIR}/traceroute; \
		[ -f Makefile ] || \
		./configure --prefix=/usr/local/v6; \
		$(MAKE) install install-man)
	(cd ${.CURDIR}/dtcp; $(MAKE) install)
	(cd ${.CURDIR}/ndp; $(MAKE) install)

.if ${OPSYS} == "FreeBSD"
.include <bsd.subdir.mk> 
.endif

	(cd ${.CURDIR}/man; $(MAKE) install)

clean:
	for i in $(SUBDIR); do\
		(cd ${.CURDIR}/$$i; $(MAKE) clean); \
	done
	(for i in $(CONFIGURE_SUBDIR); do \
		if [ -f ${.CURDIR}/$$i/Makefile ]; then \
			(cd ${.CURDIR}/$$i; $(MAKE) distclean) \
		else \
			(cd ${.CURDIR}/$$i; /bin/rm -f *.o */*.o) \
		fi \
	done)
	(cd ${.CURDIR}/dtcp; $(MAKE) clean)
	(cd ${.CURDIR}/ndp; $(MAKE) clean)
