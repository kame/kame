# $NetBSD$
# $Id: Makefile,v 1.5 2000/05/17 02:56:02 suz Exp $
#

DISTNAME=	gated-pub-ipv6-snapshot20000511
PKGNAME=	gated-ipv6-20000511
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.gated.org/net-research/gated/

MAINTAINER=	suz@kame.net
HOMEPAGE=	http://www.gated.org/

NO_PACKAGE=	"binary redistribution restricted to members"
NO_CDROM=	"binary redistribution restricted to members"

WRKSRC=		${WRKDIR}/gated-public-v6-snapshot000511
GNU_CONFIGURE=	YES
CONFIGURE_ARGS+=--enable-bgp
CONFIGURE_ARGS+=--enable-bgp4mp
CONFIGURE_ARGS+=--disable-mpbgp6
CONFIGURE_ARGS+=--enable-ospf
CONFIGURE_ARGS+=--enable-rip
CONFIGURE_ARGS+=--enable-ripng
CONFIGURE_ARGS+=--enable-gii

#pre-build:
#	(cd ${WRKSRC}; ${MAKE} depend)

post-install:
	${INSTALL_PROGRAM} ${WRKSRC}/src/gdc/gdc ${PREFIX}/sbin
	${INSTALL_PROGRAM} ${WRKSRC}/src/rip6query/rip6query ${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/src/ripquery/ripquery ${PREFIX}/bin

.include "../../mk/bsd.pkg.mk"
