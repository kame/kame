# New ports collection makefile for:    quake6
# Version required:     0.0
# Date created:         Wed Feb  2 01:07:07 JST 2000
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.3 2000/05/17 10:13:20 sumikawa Exp $
#

DISTNAME=	qf-current-snapshot
PKGNAME=	quakeforge-20000512
CATEGORIES=	games
MASTER_SITES=	http://quake.sourceforge.net/files/

MAINTAINER=	sumikawa@kame.net

USE_BZIP2=	yes
WRKSRC=		${WRKDIR}/quakeforge

USE_GMAKE=	yes
GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	"NO_ASMOPT=yes"
CONFIGURE_ARGS+=--without-opengl --disable-asmopt
CONFIGURE_ARGS+=--with-ipv6=/usr/local/v6/lib

post-extract:
	cd ${WRKSRC} && ${MV} acinclude.m4 aclocal.m4

pre-configure:
	@(cd ${WRKSRC} && ${AUTOCONF})
	@(cd ${WRKSRC} && autoheader)

.include "bsd.port.mk"
