# $NetBSD$

DISTNAME=	quake-v6-bsd-kame
PKGNAME=	quake6-0.0
CATEGORIES=	games
MASTER_SITES=	http://www.viagenie.qc.ca/quake/

MAINTAINER=	itojun@kame.net
HOMEPAGE=	http://www.viagenie.qc.ca/en/ipv6-quake.shtml

WRKSRC=		${WRKDIR}/quakeforge

post-extract:
	(cd ${WRKSRC}; find . -name \*.o -exec {$RM} {} \;)

USE_GMAKE=	yes
GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--disable-asmopt

.include "../../mk/bsd.pkg.mk"
