# New ports collection makefile for:	ppp
# Date created:		11 Apr 1999
# Whom:			shin
#
# $KAME: Makefile,v 1.2 2000/06/25 10:58:42 sumikawa Exp $
#

PORTNAME=	ppp
PORTVERSION=	990309
CATEGORIES=	www
MASTER_SITES=	ftp://ftp.kame.net/pub/kame/misc/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	ppp-v6-990708.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	shin@kame.net

WRKSRC=		${WRKDIR}/ppp-990309
PATCH_STRIP=	-p1
#MAKE_ENV=	SOCKS=YES
MAKE_FLAGS=	-DINET -DINET6
PREFIX=		/usr/local/v6

.include <bsd.port.mk>
