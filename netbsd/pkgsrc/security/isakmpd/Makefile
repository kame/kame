# $NetBSD$
#

DISTNAME=		isakmpd-000220
PKGNAME=		isakmpd-20000220
CATEGORIES=		security net
MASTER_SITES=		ftp://ftp.appli.se/pub/isakmpd/

PATCH_SITES=		ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=		isakmpd-20000220-20000427a.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=		itojun@kame.net

DEPENDS+=		openssl-0.9.4:../../security/openssl
DEPENDS+=		gmp-2.0.2:../../devel/gmp

RESTRICTED=		"Crypto; export-controlled"
MIRROR_DISTFILE=	no

ALL_TARGET=		depend all

.include "../../mk/bsd.pkg.mk"
