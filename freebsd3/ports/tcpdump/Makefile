# New ports collection makefile for:    tcpdump
# Date created:         Wed Jan 26 03:37:49 JST 2000
# Whom:                 sumikawa
#
# $KAME: Makefile,v 1.18 2000/07/19 15:50:12 sumikawa Exp $
#

PORTNAME=	tcpdump
SNAPVERSION=	2000_07_17
PORTVERSION=	${SNAPVERSION:S/_//g}
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/
DISTNAME=	${PORTNAME}-${SNAPVERSION}

MAINTAINER=	sumikawa@kame.net

BUILD_DEPENDS=	${LOCALBASE}/lib/libpcap.a:../libpcap
BUILD_DEPENDS=	autoreconf:${PORTSDIR}/devel/autoconf

GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	LIBS="-L${PREFIX}/lib"
CONFIGURE_ARGS+=--enable-ipv6

pre-configure:
	(cd ${WRKSRC}; autoreconf)

INSTALL_TARGET=	install install-man

.include <bsd.port.mk>
