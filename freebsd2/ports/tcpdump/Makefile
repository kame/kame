# New ports collection makefile for:    tcpdump
# Version required:     20000125
# Date created:         Wed Jan 26 03:37:49 JST 2000
# Whom:                 sumikawa
#
# $FreeBSD$
#

DISTNAME=	tcpdump-2000.10.09
PKGNAME=	tcpdump-20001009
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	sumikawa@kame.net

BUILD_DEPENDS=	${LOCALBASE}/lib/libpcap.a:../libpcap
BUILD_DEPENDS=	autoreconf:${PORTSDIR}/devel/autoconf

GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	LIBS="-L${PREFIX}/lib"
CONFIGURE_ARGS+=--enable-ipv6

pre-configure:
	(cd ${WRKSRC}; autoreconf)

.include <bsd.port.mk>
