# New ports collection makefile for:	libident
# Version required:	0.22
# Date created:		9 October 1995
# Whom:			torstenb@FreeBSD.ORG
#
# $Id: Makefile,v 1.1 1999/08/17 09:09:57 itojun Exp $
#

DISTNAME=	libident-0.22
PKGNAME=        libident6-0.22
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
