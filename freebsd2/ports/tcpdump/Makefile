# New ports collection makefile for:    tcpdump
# Version required:     20000125
# Date created:         Wed Jan 26 03:37:49 JST 2000
# Whom:                 sumikawa
#
# $FreeBSD$
#

DISTNAME=	tcpdump-2000_02_14
PKGNAME=	tcpdump-20000214
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	sumikawa@kame.net

BUILD_DEPENDS=	${LOCALBASE}/lib/libpcap.a:../libpcap

GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	LIBS="-L${PREFIX}/lib"
CONFIGURE_ARGS+=--enable-ipv6

pre-configure:
	(cd ${WRKSRC}; autoreconf)

INSTALL_TARGET=	install install-man

.include <bsd.port.mk>
