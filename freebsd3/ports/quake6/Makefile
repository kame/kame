# New ports collection makefile for:    quake6
# Version required:     0.0
# Date created:         Wed Feb  2 01:07:07 JST 2000
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.2 2000/02/01 17:24:41 sumikawa Exp $
#

DISTNAME=	quake-v6-bsd-kame
PKGNAME=	quake6-0.0
CATEGORIES=	games
MASTER_SITES=	http://www.viagenie.qc.ca/quake/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	quake6-00-v6-20000202a.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	sumikawa@kame.net

WRKSRC=		${WRKDIR}/quakeforge

post-extract:
	(cd ${WRKSRC}; find . -name \*.o -exec ${RM} {} \;)
	(cd ${WRKSRC}; ${RM} config.cache)

USE_GMAKE=	yes
GNU_CONFIGURE=	yes
# "bindir" setting is very non-standard for GNU autoconf
CONFIGURE_ARGS+=--disable-asmopt --bindir=/bin

.include "bsd.port.mk"
