# New ports collection makefile for:    lynx
# http://www.slcc.edu/lynx/release2-8/
# Version required:     2.8
# Date created:         12 May 1998
# Whom:                 k-sugyou
#
# $Id: Makefile,v 1.2 1999/10/08 03:37:42 itojun Exp $
#

DISTNAME=       lynx2-8-2
PKGNAME=        lynx-2.8.2.0
CATEGORIES=	www
MASTER_SITES=   http://sol.slcc.edu/lynx/release2-8-2/ \
		ftp://ftp.iij.ad.jp/pub/NetBSD/packages/distfiles/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	lynx-282-v6-19991008.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	k-sugyou@kame.net

NO_LATEST_LINK=	YES
WRKSRC=         ${WRKDIR}/lynx2-8-2
GNU_CONFIGURE=  YES
CONFIGURE_ARGS= --with-zlib
MAKEFILE=       makefile
INSTALL_TARGET= install install-help
MAN1=		lynx.1

post-install:
	chown -R ${SHAREOWN}:${SHAREGRP} ${PREFIX}/lib/lynx_help

.include <bsd.port.mk>
