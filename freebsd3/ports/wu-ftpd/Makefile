# New ports collection makefile for:	wu-ftpd
# Version required:     2.4.2-beta-18
# Date created:		18 Oct 1994
# Whom:			torstenb
#
# $Id: Makefile,v 1.1.1.1.2.1 1999/10/12 09:45:47 sumikawa Exp $
#
# REMINDER: to use ftpaccess(5) you need to specify -a in command line,
# it is changed from previous versions

DISTNAME=       wu-ftpd-2.4.2-beta-18
PKGNAME=        wu-ftpd-2.4.2b18
CATEGORIES=	net
# AUSCERT recommendation
MASTER_SITES=   ftp://ftp.academ.com/pub/wu-ftpd/private/
EXTRACT_SUFX=   .tar.Z

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	wu-ftpd-242b18-v6-980924.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=     ache@FreeBSD.org

BROKEN=		"old beta, with security hole"

do-build:
	cd ${WRKSRC} && ./build fbs

MAN1=		ftpcount.1 ftpwho.1
MAN5=		ftpaccess.5 ftphosts.5 ftpconversions.5 xferlog.5
MAN8=		ftpd.8 ftpshut.8

.include <bsd.port.mk>
