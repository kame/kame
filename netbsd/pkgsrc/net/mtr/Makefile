# $NetBSD$

DISTNAME=	mtr-0.42
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.bitwizard.nl/mtr/

PATCHFILES=	mtr-042-v6-20000506.diff.gz
PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.BitWizard.nl/mtr/

GNU_CONFIGURE=	yes
USE_GMAKE=	yes
CONFIGURE_ARGS+=--enable-ipv6

.if defined(USE_GTK)
USE_X11BASE=	yes
DEPENDS=	gtk+-1.2.1:../../x11/gtk
CONFIGURE_ARGS+=--with-gtk-prefix=${X11BASE}
.else
CONFIGURE_ARGS+=--with-gtk-prefix=/nopath
.endif

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/mtr ${PREFIX}/sbin
	${INSTALL_MAN} ${WRKSRC}/mtr.8 ${PREFIX}/man/man8

.include "../../mk/bsd.pkg.mk"
