# New ports collection makefile for:    libpcap
# Version required:     20000320
# Date created:         Wed Jan 26 03:37:49 JST 2000
# Whom:                 sumikawa
#
# $FreeBSD$
#

DISTNAME=	libpcap-2000_03_20
PKGNAME=	libpcap-20000320
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	sumikawa@kame.net

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--enable-ipv6

INSTALL_TARGET=	install install-incl install-man

pre-install:
	${MKDIR} ${PREFIX}/include/net

.include <bsd.port.mk>
