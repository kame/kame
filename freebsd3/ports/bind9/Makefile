# New ports collection makefile for:	bind9
# Version required:	9.0.0b2
# Date created:		Sat Apr 29 18:50:37 JST 2000
# Whom:			jinmei
#
# $Id: Makefile,v 1.5 2000/06/20 05:59:55 sumikawa Exp $
#

DISTNAME=	bind-9.0.0b4
PKGNAME=	bind-9.0.0.b4
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind9/9.0.0b4/

MAINTAINER=	sumikawa@kame.net

#CONFLICTS=	bind-*
#DEPENDS=	unproven-pthreads-*:../../devel/unproven-pthreads

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--with-mit-pthreads --with-kame

.include "bsd.port.mk"
