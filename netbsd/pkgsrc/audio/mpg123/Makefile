# New ports collection makefile for:	mpg123
# Version required:		0.59o
# Date created:			25 June 1997
# Whom:				Carey Jones <mcj@acquiesce.org>
#
# $Id: Makefile,v 1.2 1999/10/08 02:39:26 itojun Exp $
#

DISTNAME=	mpg123-0.59r
CATEGORIES=	audio
MASTER_SITES=	http://www-ti.informatik.uni-tuebingen.de/~hippm/mpg123/ \
		ftp://ftp.tu-clausthal.de/pub/unix/audio/mpg123/ \
		http://ftp.tu-clausthal.de/pub/unix/audio/mpg123/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	mpg123-059r-v6-19991007a.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@kame.net

MAN1=		mpg123.1

ALL_TARGET=	netbsd

.include "../../mk/bsd.pkg.mk"
