# New ports collection makefile for:	tcp_wrapper
# Version required:     7.6
# Date created:		27 Oct 1994
# Whom:			torstenb
#
# $Id: Makefile,v 1.1 1999/08/17 09:10:42 itojun Exp $
#

DISTNAME=       tcp_wrappers_7.6
PKGNAME=        tcp_wrappers6-7.6
CATEGORIES=	security net
MASTER_SITES=	ftp://ftp.porcupine.org/pub/security/

PATCH_SITES=	http://www.imasy.or.jp/~ume/ipv6/
PATCHFILES=	tcp_wrappers_7.6-ipv6-1.3.diff.gz
PATCH_DIST_STRIP=	-p2

MAINTAINER=	ume@mahoroba.org

ALL_TARGET=	freebsd
MAN3=		hosts_access.3
MAN5=		hosts_access.5 hosts_options.5
MAN8=		tcpd.8 tcpdchk.8 tcpdmatch.8

PREFIX=		/usr/local/v6

.include <bsd.port.mk>
