#	$NetBSD: Makefile,v 1.27.4.1 2000/09/30 06:21:41 simonb Exp $

#PCAPDIR=${.CURDIR}/../../../lib/libpcap

PROG=	pppd
SRCS=	auth.c cbcp.c ccp.c chap.c chap_ms.c demand.c eui64.c fsm.c \
	ipcp.c ipv6cp.c ipxcp.c lcp.c magic.c main.c multilink.c options.c \
	sys-bsd.c tdb.c tty.c upap.c utils.c

.PATH:	${PCAPDIR}
MAN=	pppd.8
BINMODE=4555
BINOWN=	root

#LDADD+=-lpcap
#DPADD+=${LIBPCAP}
LDADD+=	-lcrypt -lutil
DPADD+=	${LIBCRYPT} ${LIBUTIL}
CPPFLAGS+= -I. -DHAVE_PATHS_H 
#CPPFLAGS+= -I${PCAPDIR} -DPPP_FILTER
CPPFLAGS+= -DCBCP_SUPPORT -DCHAPMS -DUSE_CRYPT -DMSLANMAN
CPPFLAGS+= -DINET6

LDADD+=	-L${.CURDIR}/../../../lib/libinet6 \
	-L${.CURDIR}/../../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
