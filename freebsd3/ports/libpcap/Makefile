# New ports collection makefile for:    libpcap
# Date created:         Wed Jan 26 03:37:49 JST 2000
# Whom:                 sumikawa
#
# $KAME: Makefile,v 1.20 2000/10/15 09:53:46 sumikawa Exp $
#

PORTNAME=	libpcap
SNAPVERSION=	2000.10.09
PORTVERSION=	${SNAPVERSION:S/.//g}
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/
DISTNAME=	${PORTNAME}-${SNAPVERSION}

MAINTAINER=	sumikawa@kame.net

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--enable-ipv6

.include <bsd.port.mk>
