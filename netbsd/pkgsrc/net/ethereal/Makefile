# $NetBSD: Makefile,v 1.11 1999/10/07 17:41:56 tron Exp $
#

DISTNAME=		ethereal-0.8.3
CATEGORIES=		net
MASTER_SITES=		http://ethereal.zing.org/distribution/

MAINTAINER=		packages@netbsd.org
HOMEPAGE=		http://ethereal.zing.org/

DEPENDS=		gtk+-1.2.1:../../x11/gtk
BUILD_DEPENDS+=		${LOCALBASE}/bin/perl:../../lang/perl5

USE_GMAKE=		yes
USE_X11=		yes
GNU_CONFIGURE=		yes
CONFIGURE_ARGS+=	--with-gtk-prefix=${X11BASE}
#CONFIGURE_ARGS+=	--disable-zlib
CONFIGURE_ARGS+=	--disable-snmp

.include "../../mk/bsd.pkg.mk"
