# New ports collection makefile for:	vic
# Version required:	2.8v6
# Date created:		1999/8/7
# Whom:			ichiro
#
# $Id: Makefile,v 1.3 1999/09/26 03:00:28 itojun Exp $
#

DISTNAME=	vic-2.8v6
CATEGORIES=	mbone tk80
MASTER_SITES=	http://irl.cs.ucla.edu/software/IPv6/

DISTFILES=	vic-2.8v6.tar.gz

PATCH_SITES=            http://www.v6.csi2.net/setup/mcast/patch/
PATCHFILES=             vic-2.8v6-kame-19990925.patch
PATCH_DIST_STRIP=       -p1

MAINTAINER=	ichiro@ichiro.org

LIB_DEPENDS=	tk80.1:${PORTSDIR}/x11-toolkits/tk80

USE_AUTOCONF=	yes
USE_X_PREFIX=	yes
MAN1=		vic.1

pre-build:
	${CP} ${FILESDIR}/grabber-scc.cc  ${WRKSRC}

post-install:
	strip ${PREFIX}/bin/vic
	strip ${PREFIX}/bin/histtolut

.include <bsd.port.mk>
