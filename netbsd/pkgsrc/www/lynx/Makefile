# $NetBSD: Makefile,v 1.12 1998/08/20 15:17:30 tsarna Exp $
#

DISTNAME=       lynx2-8-2
PKGNAME=        lynx-2.8.2.0
WRKSRC=         ${WRKDIR}/lynx2-8-2
CATEGORIES=	www
MASTER_SITES=   http://sol.slcc.edu/lynx/current/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	lynx-282-v6-19991008.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	packages@netbsd.org
HOMEPAGE=	http://sol.slcc.edu/lynx/

CONFLICTS=	lynx-2.8rel.2 lynx-2.8.1*

#DEPENDS+=	ncurses-1.9.9g:../../devel/ncurses

#CONFIGURE_ARGS+= --with-screen=ncurses --with-zlib --libdir="${PREFIX}/etc"
CONFIGURE_ARGS+= --with-zlib --libdir="${PREFIX}/etc"
GNU_CONFIGURE=  YES
INSTALL_TARGET= install install-help
MAKEFILE=       makefile

post-install:
	chown -R ${SHAREOWN}:${SHAREGRP} ${PREFIX}/etc/lynx_help

.include "../../mk/bsd.pkg.mk"
