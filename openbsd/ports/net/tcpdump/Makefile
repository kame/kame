# $NetBSD$

DISTNAME=	tcpdump-2000_04_17
PKGNAME=	tcpdump-20000417
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.tcpdump.org/

BUILD_DEPENDS+=	${PREFIX}/lib/libpcap.a:../../net/libpcap
BUILD_DEPENDS+=	autoconf:../../devel/autoconf
BUILD_DEPENDS+=	${PREFIX}/bin/gtar:${PORTSDIR}/archivers/gtar

TAR=		gtar
GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	LIBS="-L${PREFIX}/lib"
CONFIGURE_ARGS+=--enable-ipv6

pre-configure:
	(cd ${WRKSRC}; autoreconf)

INSTALL_TARGET=	install install-man

.include <bsd.port.mk>
