# New ports collection makefile for:	netris
# Version required:	0.5
# Date created:	1 August 1996
# Whom:	desmo
#
# $FreeBSD: ports/games/netris/Makefile,v 1.5 2000/02/09 04:17:45 sumikawa Exp $
#

DISTNAME=		netris-0.5
#CATEGORIES=		games ipv6
CATEGORIES=		games
MASTER_SITES=		ftp://ftp.netris.org/pub/netris/

PATCH_SITES=		ftp://ftp2.v6.linux.or.jp/pub/Linux/IPv6-2/netris/ \
			http://ftp2.v6.linux.or.jp/pub/Linux/IPv6-2/netris/
PATCHFILES=		netris-0.5-v6-19991206a.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=		sumikawa@kame.net

HAS_CONFIGURE=		yes
CONFIGURE_SCRIPT=	Configure
CONFIGURE_ARGS=		--cc '${CC}' --copt '${CFLAGS}'
MAN1=			netris.1

.include <bsd.port.pre.mk>

#.if ${OSVERSION} >= 400014
CONFIGURE_ARGS+=	--enable-ipv6
#.else
#CONFIGURE_ARGS+=	--disable-ipv6
#.endif

post-install:
	${INSTALL_MAN} ${FILESDIR}/netris.1 ${PREFIX}/man/man1

.include <bsd.port.post.mk>
