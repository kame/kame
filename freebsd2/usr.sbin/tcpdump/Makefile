SRCDIR=	${.CURDIR}/../../kame/tcpdump

PROG=	tcpdump
SRCS+=	tcpdump.c \
	print-arp.c print-atalk.c print-atm.c print-bootp.c \
	print-decnet.c print-domain.c print-dvmrp.c print-egp.c \
	print-ether.c print-fddi.c print-gre.c print-icmp.c \
	print-igrp.c print-ip.c print-ipx.c print-isoclns.c print-krb.c \
	print-llc.c print-nfs.c print-ntp.c print-null.c print-ospf.c \
	print-pim.c print-ppp.c print-raw.c print-rip.c print-sl.c \
	print-snmp.c print-sunrpc.c print-tcp.c print-tftp.c print-udp.c \
	print-wb.c addrtoname.c bpf_dump.c gmt2local.c machdep.c \
	parsenfsfh.c util.c savestr.c setsignal.c \
	print-esp.c print-ah.c print-vjc.c print-isakmp.c print-chdlc.c \
	print-ipcomp.c print-mobile.c print-l2tp.c print-bgp.c \
	print-ascii.c print-telnet.c
SRCS+=	print-ip6.c print-ip6opts.c print-ripng.c print-icmp6.c print-frag6.c \
	print-rt6.c print-ospf6.c print-dhcp6.c
SRCS+= version.c

MAN1=	tcpdump.1

INCLS=	-I${SRCDIR}/../libpcap -I${SRCDIR} -I${.CURDIR}
# workarund to invite gnuc.h
INCLS+=	-I${SRCDIR}/lbl
# workarund to invite latest net/bpf.h
INCLS+=	-I${SRCDIR}/../libpcap/bpf
DEFS =  -DHAVE_FCNTL_H=1 -DHAVE_MEMORY_H=1 -DTIME_WITH_SYS_TIME=1 -DHAVE_NET_SLIP_H=1 -DINET6=1 -DHAVE_LIBINET6=1 -DHAVE_VFPRINTF=1 -DHAVE_STRCASECMP=1 -DHAVE_ETHER_NTOA=1 -DHAVE_SETLINEBUF=1 -DHAVE_LIBZ=1 -DHAVE_ZLIB_H=1 -DHAVE_NETINET6_IPCOMP_H=1 -DRETSIGTYPE=void -DRETSIGVAL= -DHAVE_SIGACTION=1 -DHAVE_SOCKADDR_SA_LEN=1 -DLBL_ALIGN=1  -DHAVE_FDDI -DHAVE_SIN6_LEN=1 -DHAVE_SIN_LEN=1 -DINCLUDE_PATH_OPENSSL=1
CFLAGS+=	-O2
CFLAGS+=	${DEFS} ${INCLS}

LDADD+=	-lz
DPADD+=	${LIBZ}
LDADD+=	-L${.CURDIR}/../../lib/libpcap -lpcap
DPADD+=	${.CURDIR}/../../lib/libpcap/libpcap.a
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

# crypto support - need OpenSSL 0.9.4
.if exists(/usr/local/lib/libcrypto.a)
CFLAGS+=-DCRYPTO=1
.if exists(/usr/local/include/openssl/rc5.h)
CFLAGS+=-DHAVE_OPENSSL_RC5_H=1
.endif
.if exists(/usr/local/include/openssl/cast.h)
CFLAGS+=-DHAVE_OPENSSL_CAST_H=1
.endif
CFLAGS+=-I/usr/local/include
LDADD+=	-L/usr/local/lib -lcrypto
DPADD+=	/usr/local/lib/libcrypto.a
.elif exists(/usr/local/ssl/lib/libcrypto.a)
CFLAGS+=-DCRYPTO=1
.if exists(/usr/local/ssl/include/openssl/rc5.h)
CFLAGS+=-DHAVE_OPENSSL_RC5_H=1
.endif
.if exists(/usr/local/ssl/include/openssl/cast.h)
CFLAGS+=-DHAVE_OPENSSL_CAST_H=1
.endif
CFLAGS+=-I/usr/local/ssl/include
LDADD+=	-L/usr/local/ssl/lib -lcrypto
DPADD+=	/usr/local/ssl/lib/libcrypto.a
.endif

version.c: VERSION
	@rm -f $@
	sed -e 's/.*/char version[] = "&";/' $> > $@

.PATH:	${SRCDIR}

.include <bsd.prog.mk>

CLEANFILES+=	version.c
