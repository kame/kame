# New ports collection makefile for:	libident
# Date created:		9 October 1995
# Whom:			torstenb@FreeBSD.ORG
#
# $KAME: Makefile,v 1.2 2000/06/25 10:58:36 sumikawa Exp $
#

PORTNAME=	libident
PORTVERSION=	0.22
CATEGORIES=	devel net security
MASTER_SITES=	ftp://ftp.lysator.liu.se/pub/ident/libs/

PATCH_SITES=	http://www.imasy.or.jp/~ume/ipv6/
PATCHFILES=	libident-0.22-ipv6-1.0.diff.gz
PATCH_DIST_STRIP=	-p0

MAINTAINER=	ume@mahoroba.org

ALL_TARGET=	freebsd
MAN3=		ident.3

PREFIX=		/usr/local/v6

.include <bsd.port.mk>
