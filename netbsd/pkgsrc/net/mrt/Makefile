# New ports collection makefile for:	mrt
# Version required:	1.5.2a
# Date created:		Sat Jun  6 00:09:52 JST 1998
# Whom:			Jun-ichiro itojun Itoh <itojun@itojun.org>
#
# $Id: Makefile,v 1.6 2000/08/15 12:30:05 itojun Exp $
#

DISTNAME=	mrt-${VERBASE}-Aug11
PKGNAME=	mrt-${VERBASE}.20000811
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.merit.edu/net-research/mrt/

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.mrtd.net/

FIND?=		/usr/bin/find

WRKSRC=		${WRKDIR}/mrt/src
GNU_CONFIGURE=	yes

PLIST_SRC=	${WRKSRC}/.PLIST_SRC
VERBASE=	2.2.2a

# nuke yet-to-be-ready directories, configure.in is written in a strange way
post-extract:
	(cd ${WRKSRC}/programs; ${RM} -fr route_tracker sospf srip)

post-install:
	${CAT} ${PKGDIR}/PLIST.pre >${PLIST_SRC}
	${MKDIR} ${PREFIX}/share/examples/mrt
	${INSTALL_DATA} ${WRKSRC}/programs/*/*.conf \
		${PREFIX}/share/examples/mrt
	(cd ${PREFIX}; ${FIND} share/examples/mrt -type f -print \
		>> ${PLIST_SRC})
	(cd ${PREFIX}; ${FIND} -d share/examples/mrt -type d -print | \
		${SED} -e "s/^/@dirrm /" >>${PLIST_SRC})

.include "../../mk/bsd.pkg.mk"
