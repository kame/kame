# New ports collection makefile for:	vic
# Date created:		1999/8/7
# Whom:			ichiro
#
# $KAME: Makefile,v 1.5 2000/06/25 10:58:49 sumikawa Exp $
#

PORTNAME=	vic
PORTVERSION=	2.8v6
CATEGORIES=	mbone tk82
MASTER_SITES=	http://irl.cs.ucla.edu/software/IPv6/

PATCH_SITES=	http://www.v6.csi2.net/setup/mcast/patch/
PATCHFILES=	vic-2.8v6-kame-19990925.patch
PATCH_DIST_STRIP=	-p1

MAINTAINER=	ichiro@ichiro.org

LIB_DEPENDS=	tk82.1:${PORTSDIR}/x11-toolkits/tk82

USE_AUTOCONF=	yes
USE_X_PREFIX=	yes
MAN1=		vic.1

pre-build:
	${CP} ${FILESDIR}/grabber-scc.cc  ${WRKSRC}

post-install:
	strip ${PREFIX}/bin/vic
	strip ${PREFIX}/bin/histtolut

.include <bsd.port.mk>
