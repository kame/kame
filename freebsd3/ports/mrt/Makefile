# New ports collection makefile for:	mrt
# Date created:		Sat Jun  6 00:09:52 JST 1998
# Whom:			Jun-ichiro itojun Hagino <itojun@itojun.org>
#
# $FreeBSD: ports/net/mrt/Makefile,v 1.4 2000/01/11 19:53:22 sumikawa Exp $
#

PORTNAME=	mrt
PORTVERSION=	2.2.2a
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.merit.edu/net-research/mrt/
DISTNAME=	${PORTNAME}-${PORTVERSION}-Aug11

MAINTAINER=	itojun@itojun.org

WRKSRC=		${WRKDIR}/mrt/src
GNU_CONFIGURE=	yes
USE_AUTOCONF=	yes

MAN8=	mrtd.8
EXAMPLES=	programs/bgpsim/bgpsim.conf programs/bgpsim/bgpsim6.conf \
		programs/mrtd/mrtd.conf programs/mrtd/mrtd.ripng.conf \
		programs/mrtd/solaris.ripng.conf

# nuke yet-to-be-ready directories, configure.in is written in a strange way
post-extract:
	(cd ${WRKSRC}/programs; ${RM} -fr route_tracker sospf srip)

post-install:
	${MKDIR} ${PREFIX}/share/examples/mrt
	for i in ${EXAMPLES}; do \
		${INSTALL_DATA} ${WRKSRC}/$$i ${PREFIX}/share/examples/mrt; \
	done

.include <bsd.port.mk>
