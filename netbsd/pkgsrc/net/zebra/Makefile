# New ports collection makefile for:	zebra
# Version required:	0.87
# Date created:		So  31 Mai 1998 11:00:30 CEST
# Whom:			Andreas Klemm <andreas@klemm.gtn.com>
#
# $Id: Makefile,v 1.15 2000/08/17 10:29:12 itojun Exp $
#

DISTNAME=	zebra-0.88-pre2
PKGNAME=	zebra-0.88p2
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.zebra.org/pub/tmp/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.zebra.org/

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--sysconfdir=${PREFIX}/etc/zebra

.include "../../mk/bsd.pkg.mk"
