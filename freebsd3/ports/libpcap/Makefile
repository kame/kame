# New ports collection makefile for:    libpcap
# Date created:         Wed Jan 26 03:37:49 JST 2000
# Whom:                 sumikawa
#
# $KAME: Makefile,v 1.17 2000/07/19 15:50:11 sumikawa Exp $
#

PORTNAME=	libpcap
SNAPVERSION=	2000_07_17
PORTVERSION=	${SNAPVERSION:S/_//g}
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/
DISTNAME=	${PORTNAME}-${SNAPVERSION}

MAINTAINER=	sumikawa@kame.net

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--enable-ipv6

INSTALL_TARGET=	install install-incl install-man

pre-install:
	${MKDIR} ${PREFIX}/include/net

.include <bsd.port.mk>
