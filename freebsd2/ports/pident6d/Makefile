# New ports collection makefile for:	pidentd
# Version required:     2.8.2
# Date created:		19 Oct 1994
# Whom:			torstenb
#
# $Id: Makefile,v 1.1.1.1 1999/08/09 01:37:17 itojun Exp $
#

DISTNAME=       pidentd-2.8.5
PKGNAME=        pidentd6-2.8.5
CATEGORIES=	security net
MASTER_SITES=	ftp://ftp.lysator.liu.se/pub/ident/servers/ \
		ftp://ftp.fu-berlin.de/unix/security/ident/servers/

PATCH_SITES=	http://www.imasy.or.jp/~ume/ipv6/
PATCHFILES=	pidentd-2.8.5-ipv6-1.0.diff.gz
PATCH_DIST_STRIP=	-p0

MAINTAINER=	ume@mahoroba.org

ALL_TARGET=     freebsd
MAKE_ENV=	REALPREFIX=${PREFIX}
#MAN8=		identd.8 idecrypt.8
MAN8=		ident6d.8

PREFIX=		/usr/local/v6

# Uncomment to activate the use of verifiable "cookies".  The idea is to be
# able to detect fake "logs" intended to get your innocent users in trouble.
# Naturally, since it uses libdes, you must have the "secure" dist installed.
# USE_DES=	true
# This option is not yet supported by IPv6 patch.

.if defined(USE_DES)
ADD_GDEFS=	-DINCLUDE_CRYPT
ADD_GLIBS=	-ldes
MAKE_ENV+=	ADD_GDEFS="${ADD_GDEFS}" ADD_GLIBS="${ADD_GLIBS}"
.endif

.include <bsd.port.mk>
