# New ports collection makefile for:	zebra
# Version required:	0.85
# Date created:		So  31 Mai 1998 11:00:30 CEST
# Whom:			Andreas Klemm <andreas@klemm.gtn.com>
#
# $Id: Makefile,v 1.11 2000/03/20 23:54:53 itojun Exp $
#

DISTNAME=	zebra-0.85a
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.zebra.org/pub/tmp/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.zebra.org/

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--sysconfdir=${PREFIX}/etc/zebra
#CONFIGURE_ARGS+=--disable-ospf6d

.include "../../mk/bsd.pkg.mk"
