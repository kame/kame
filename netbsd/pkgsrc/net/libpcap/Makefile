# $NetBSD$

DISTNAME=	libpcap-2000_01_25
PKGNAME=	libpcap-20000125
CATEGORIES=	net
MASTER_SITES=	http://www.tcpdump.org/weekly/

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.tcpdump.org/

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--enable-ipv6

INSTALL_TARGET=	install install-incl install-man

pre-install:
	${MKDIR} ${PREFIX}/include/net

.include "../../mk/bsd.pkg.mk"
