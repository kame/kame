# New ports collection makefile for:	bind9
# Version required:	9.0.0b1
# Date created:		Sun Feb  6 02:55:31 JST 2000
# Whom:			sumikawa
#
# $Id: Makefile,v 1.1 2000/02/05 18:03:35 sumikawa Exp $
#

DISTNAME=	bind-9.0.0b1
PKGNAME=	bind-9.0.0.b1
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind9/9.0.0b1/

MAINTAINER=	sumikawa@kame.net

#CONFLICTS=	bind-*
#DEPENDS=	unproven-pthreads-*:../../devel/unproven-pthreads

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--with-mit-pthreads --with-kame

.include "bsd.port.mk"
