# $NetBSD$

DISTNAME=	libpcap-2000.08.28
PKGNAME=	libpcap-20000828
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.tcpdump.org/

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--enable-ipv6

INSTALL_TARGET=	install

pre-install:
	${MKDIR} ${PREFIX}/include/net

.include "../../mk/bsd.pkg.mk"
