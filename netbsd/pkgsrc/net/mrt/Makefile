# New ports collection makefile for:	mrt
# Version required:	1.5.2a
# Date created:		Sat Jun  6 00:09:52 JST 1998
# Whom:			Jun-ichiro itojun Itoh <itojun@itojun.org>
#
# $Id: Makefile,v 1.5 2000/08/15 11:39:01 itojun Exp $
#

DISTNAME=	mrt-${VERBASE}-Aug11
PKGNAME=	mrt-${VERBASE}.20000811
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.merit.edu/net-research/mrt/

MAINTAINER=	itojun@itojun.org

WRKSRC=		${WRKDIR}/mrt/src
GNU_CONFIGURE=	yes

VERBASE=	2.2.2a

EXAMPLES=	programs/bgpsim/bgpsim.conf programs/bgpsim/bgpsim6.conf \
		programs/mrtd/mrtd.conf programs/mrtd/mrtd.pim.conf \
		programs/mrtd/mrtd.ripng.conf programs/mrtd/solaris.ripng.conf \
		programs/ricd/ricd.conf

# nuke yet-to-be-ready directories, configure.in is written in a strange way
post-extract:
	(cd ${WRKSRC}/programs; ${RM} -fr route_tracker sospf srip)

post-install:
	${MKDIR} ${PREFIX}/share/examples/mrt
	for i in ${EXAMPLES}; do \
		${INSTALL_DATA} ${WRKSRC}/$$i ${PREFIX}/share/examples/mrt; \
	done

.include "../../mk/bsd.pkg.mk"
