# $NetBSD$

DISTNAME=	tcpdump-2000.08.14
PKGNAME=	tcpdump-20000814
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.tcpdump.org/

DEPENDS+=	libpcap-*:../../net/libpcap
BUILD_DEPENDS+=	autoconf:../../devel/autoconf

GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	LIBS="-L${PREFIX}/lib"
CONFIGURE_ARGS+=--enable-ipv6

pre-configure:
	(cd ${WRKSRC}; autoreconf)

INSTALL_TARGET=	install

.include "../../mk/bsd.pkg.mk"
