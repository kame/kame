# $NetBSD$

DISTNAME=	tcpdump-2000_02_14
PKGNAME=	tcpdump-20000214
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

INSTALL_TARGET=	install install-man

.include "../../mk/bsd.pkg.mk"
