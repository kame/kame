# New ports collection makefile for:    lynx
# http://www.slcc.edu/lynx/release2-8/
# Version required:     2.8
# Date created:         12 May 1998
# Whom:                 k-sugyou
#
# $Id: Makefile,v 1.1 1999/08/17 09:09:58 itojun Exp $
#

DISTNAME=       lynx2.8.1rel.1
PKGNAME=        lynx-2.8.1.1
CATEGORIES=	www
MASTER_SITES=   http://sol.slcc.edu/lynx/current/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	lynx-281-v6-19990520.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	k-sugyou@kame.net

NO_LATEST_LINK=	YES
WRKSRC=         ${WRKDIR}/lynx2-8-1
GNU_CONFIGURE=  YES
CONFIGURE_ARGS= --with-zlib
MAKEFILE=       makefile
INSTALL_TARGET= install install-help
MAN1=		lynx.1

post-install:
	chown -R ${SHAREOWN}:${SHAREGRP} ${PREFIX}/lib/lynx_help

.include <bsd.port.mk>
