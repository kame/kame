# New ports collection makefile for:	wyvern
# Date created:				Sun Jun 25 19:38:52 JST 2000
# Whom:					sumikawa
#
# $KAME: Makefile,v 1.2 2000/06/25 10:58:51 sumikawa Exp $
#

PORTNAME=	wyvern
PORTVERSION=	0.7.7
CATEGORIES=	net
MASTER_SITES=	http://www.MysticWALL.com/software/src/

MAINTAINER=	sumikawa@kame.net

HAS_CONFIGURE=	yes
CONFIGURE_ARGS=	--enable-ipv6
CONFIGURE_ENV=	LDFLAGS="-L/usr/local/v6/lib" LIBS="-linet6"
USE_BZIP2=	yes

.include <bsd.port.mk>
