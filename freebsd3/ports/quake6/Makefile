# New ports collection makefile for:    quake6
# Version required:     0.0
# Date created:         Wed Feb  2 01:07:07 JST 2000
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.1 2000/02/01 16:19:56 sumikawa Exp $
#

DISTNAME=	quake-v6-bsd-kame
PKGNAME=	quake6-0.0
CATEGORIES=	games
MASTER_SITES=	http://www.viagenie.qc.ca/quake/

MAINTAINER=	sumikawa@kame.net

WRKSRC=		${WRKDIR}/quakeforge

post-extract:
	(cd ${WRKSRC}; find . -name \*.o -exec ${RM} {} \;)

USE_GMAKE=	yes
GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--disable-asmopt

.include "bsd.port.mk"
