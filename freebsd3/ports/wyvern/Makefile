# New ports collection makefile for:    wyvern
# Date created:         
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.1 2000/06/23 16:00:45 sumikawa Exp $
#

DISTNAME=	wyvern-0.7.7
CATEGORIES=	net
MASTER_SITES=	http://www.MysticWALL.com/software/src/

MAINTAINER=	sumikawa@kame.net

HAS_CONFIGURE=	yes
CONFIGURE_ARGS=	--enable-ipv6
CONFIGURE_ENV=	LDFLAGS="-L/usr/local/v6/lib" LIBS="-linet6"
USE_BZIP2=	yes

.include <bsd.port.mk>
