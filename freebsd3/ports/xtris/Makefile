# New ports collection makefile for:    xtris
# Version required:     1.15
# Date created:         24. Sep 97
# Whom:                 sec@42.org
#
# $FreeBSD: ports/games/xtris/Makefile,v 1.5 2000/01/24 01:35:40 sumikawa Exp $
#

DISTNAME=       xtris-1.15
#CATEGORIES=	games ipv6
CATEGORIES=	games
MASTER_SITES=	http://www.iagora.com/~espel/xtris/

PATCH_SITES=	ftp://ftp2.v6.linux.or.jp/pub/Linux/IPv6-2/xtris/ \
		http://ftp2.v6.linux.or.jp/pub/Linux/IPv6-2/xtris/
PATCHFILES=	xtris-1.15-v6-19991218.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	sec@42.org

RESTRICTED=	"Possible trademark infringement"
WRKSRC=		${WRKDIR}/xtris

USE_X_PREFIX=	yes
MAN6=		xtris.6 xtserv.6 xtbot.6

.include <bsd.port.pre.mk>

#.if ${OSVERSION} >= 400014
MAKE_ENV=	IPV6_CFLAGS="-DINET6"
MAKE_ENV+=	IPV6_LDFLAGS="-L/usr/local/v6/lib -linet6"
#.endif

.include <bsd.port.post.mk>
