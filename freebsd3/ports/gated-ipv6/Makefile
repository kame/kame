# New ports collection makefile for:	gated-ipv6
# Date created:		Sat May 13 16:35:26 JST 2000
# Whom:			suz
#
# $KAME: Makefile,v 1.5 2000/06/25 10:58:32 sumikawa Exp $

PORTNAME=	gated-ipv6
PORTVERSION=	20000511
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.gated.org/net-research/gated/
DISTNAME=	gated-pub-ipv6-snapshot20000511

MAINTAINER=	suz@kame.net

NO_PACKAGE=	"binary redistribution restricted to members"
NO_CDROM=	"binary redistribution restricted to members"

WRKSRC=		${WRKDIR}/gated-public-v6-snapshot000511
GNU_CONFIGURE=	YES
CONFIGURE_ARGS+=--enable-bgp
CONFIGURE_ARGS+=--enable-bgp4mp
CONFIGURE_ARGS+=--disable-mpbgp6
CONFIGURE_ARGS+=--enable-rip
CONFIGURE_ARGS+=--enable-ripng
CONFIGURE_ARGS+=--enable-ospf
CONFIGURE_ARGS+=--enable-gii

post-install:
	${INSTALL_PROGRAM} ${WRKSRC}/src/gdc/gdc ${PREFIX}/sbin
	${INSTALL_PROGRAM} ${WRKSRC}/src/rip6query/rip6query ${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/src/ripquery/ripquery ${PREFIX}/bin

.include <bsd.port.mk>
