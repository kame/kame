# New ports collection makefile for:    libpcap
# Version required:     20000125
# Date created:         Wed Jan 26 03:37:49 JST 2000
# Whom:                 sumikawa
#
# $FreeBSD$
#

DISTNAME=	libpcap-2000.10.09
PKGNAME=	libpcap-20001009
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	sumikawa@kame.net

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--enable-ipv6

pre-install:
	${MKDIR} ${PREFIX}/include/net

.include <bsd.port.mk>
