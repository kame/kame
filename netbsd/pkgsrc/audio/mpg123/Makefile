# New ports collection makefile for:	mpg123
# Version required:		0.59o
# Date created:			25 June 1997
# Whom:				Carey Jones <mcj@acquiesce.org>
#
# $Id: Makefile,v 1.3 2000/02/18 11:08:02 itojun Exp $
#

DISTNAME=	mpg123-0.59r
CATEGORIES=	audio
MASTER_SITES=	http://www-ti.informatik.uni-tuebingen.de/~hippm/mpg123/ \
		ftp://ftp.tu-clausthal.de/pub/unix/audio/mpg123/ \
		http://ftp.tu-clausthal.de/pub/unix/audio/mpg123/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	mpg123-059r-v6-20000111.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@kame.net

MAN1=		mpg123.1

MAKE_ENV+=	CPPFLAGS=-DINET6 IPV6LIBDIR=-L/usr/local/v6/lib IPV6LIB=-linet6

ALL_TARGET=	netbsd

.include "../../mk/bsd.pkg.mk"
