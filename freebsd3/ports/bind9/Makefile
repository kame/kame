# New ports collection makefile for:	bind9
# Date created:		Sat Apr 29 18:50:37 JST 2000
# Whom:			jinmei
#
# $Id: Makefile,v 1.6 2000/06/25 10:58:31 sumikawa Exp $
#

PORTNAME=	bind
PORTVERSION=	9.0.0b4
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind9/9.0.0b4/

MAINTAINER=	sumikawa@kame.net

#CONFLICTS=	bind-*
#DEPENDS=	unproven-pthreads-*:../../devel/unproven-pthreads

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--with-mit-pthreads --with-kame

.include "bsd.port.mk"
