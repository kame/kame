# New ports collection makefile for:    mMosaic
# Date created:         Fri Apr 14 10:36:57 JST 2000
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.1 2000/04/14 02:55:06 sumikawa Exp $
#

DISTNAME=       mMosaic-3.4.16
PKGNAME=        mmosaic-3.4.16
CATEGORIES=	www
MASTER_SITES=	ftp://tsi.enst.fr/pub/multicast/mMosaic/

REQUIRES_MOTIF=	yes

MAINTAINER=	sumikawa@kame.net

LIB_DEPENDS=	jpeg.9:${PORTSDIR}/graphics/jpeg \
		png.3:${PORTSDIR}/graphics/png

WRKSRC=		${WRKDIR}/${DISTNAME:S/-/-src-/}
#CONFIGURE_ARGS+= --with-ipv6-libraries=/usr/local/v6/lib
#CONFIGURE_ARGS+= --with-ipv6-libname=inet6

.include <bsd.port.mk>
