# New ports collection makefile for:	netris
# Version required:	0.4
# Date created:	1 August 1996
# Whom:	desmo
#
# $FreeBSD: ports/games/netris/Makefile,v 1.2 1999/08/25 06:04:08 obrien Exp $
# $Id: Makefile,v 1.1 1999/12/20 07:29:03 sumikawa Exp $
#

DISTNAME=		netris-0.5
CATEGORIES=		games
MASTER_SITES=		ftp://ftp.netris.org/pub/netris/

PATCH_SITES=		ftp://ftp2.v6.linux.or.jp/pub/Linux/IPv6-2/netris/
PATCHFILES=		netris-0.5-v6-19991206a.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=		sumikawa@kame.net

HAS_CONFIGURE=		yes
CONFIGURE_SCRIPT=	Configure
MAN1=			netris.1

post-install:
	${INSTALL_MAN} ${FILESDIR}/netris.1 ${PREFIX}/man/man1

.include <bsd.port.mk>
