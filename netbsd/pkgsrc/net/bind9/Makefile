# $NetBSD$

DISTNAME=	bind-9.0.0rc1
PKGNAME=	bind-9.0.0.rc1
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind9/9.0.0rc1/

MAINTAINER=	itojun@kame.net
HOMEPAGE=	http://www.isc.org/

#CONFLICTS=	bind-*
DEPENDS=	unproven-pthreads-*:../../devel/unproven-pthreads

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--with-mit-pthreads --with-kame

.include "../../mk/bsd.pkg.mk"
