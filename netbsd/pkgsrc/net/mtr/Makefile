# $NetBSD$

DISTNAME=	mtr-0.41
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.bitwizard.nl/mtr/

PATCHFILES=	mtr-041-v6-19990903b.diff.gz
PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.BitWizard.nl/mtr/

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--enable-ipv6

.if defined(USE_GTK)
USE_X11BASE=	yes
DEPENDS=	gtk+-1.2.1:../../x11/gtk
CONFIGURE_ARGS+=--with-gtk-prefix=${X11BASE}
.else
CONFIGURE_ARGS+=--with-gtk-prefix=/nopath
.endif

.include "../../mk/bsd.pkg.mk"
