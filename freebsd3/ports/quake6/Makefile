# New ports collection makefile for:    quakeforge
# Date created:         Wed Feb  2 01:07:07 JST 2000
# Whom:                 sumikawa
#
# $KAME: Makefile,v 1.4 2000/06/25 10:58:43 sumikawa Exp $
#

PORTNAME=	quakeforge
PORTVERSION=	20000512
CATEGORIES=	games
MASTER_SITES=	http://quake.sourceforge.net/files/
DISTNAME=	qf-current-snapshot

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
