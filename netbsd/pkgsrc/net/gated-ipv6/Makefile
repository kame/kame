# $NetBSD$
# $Id: Makefile,v 1.3 2000/02/08 16:09:19 itojun Exp $
#

DISTNAME=	gated-pub-ipv6-snapshot20000203
PKGNAME=	gated-ipv6-20000203
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.gated.org/net-research/gated/

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.gated.org/

NO_PACKAGE=	"binary redistribution restricted to members"
NO_CDROM=	"binary redistribution restricted to members"

WRKSRC=		${WRKDIR}/gated-public-v6-snapshot000203
GNU_CONFIGURE=	YES
CONFIGURE_ARGS+=--disable-bgp4mp
CONFIGURE_ARGS+=--disable-bgp
CONFIGURE_ARGS+=--disable-mpbgp
CONFIGURE_ARGS+=--disable-ospf
CONFIGURE_ARGS+=--disable-gii

post-install:
	${INSTALL_PROGRAM} ${WRKSRC}/src/gdc/gdc ${PREFIX}/sbin
	${INSTALL_PROGRAM} ${WRKSRC}/src/gated/filter ${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/src/rip6query/rip6query ${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/src/ripquery/ripquery ${PREFIX}/bin

.include "../../mk/bsd.pkg.mk"
