# New ports collection makefile for:	bind9
# Version required:	9.0.0b2
# Date created:		Sat Apr 29 18:50:37 JST 2000
# Whom:			jinmei
#
# $Id: Makefile,v 1.3 2000/04/29 09:50:22 jinmei Exp $
#

DISTNAME=	bind-9.0.0b2
PKGNAME=	bind-9.0.0.b2
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind9/9.0.0b2/

MAINTAINER=	sumikawa@kame.net

#CONFLICTS=	bind-*
#DEPENDS=	unproven-pthreads-*:../../devel/unproven-pthreads

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--with-mit-pthreads --with-kame

.include "bsd.port.mk"
