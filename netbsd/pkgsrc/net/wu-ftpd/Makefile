# New ports collection makefile for:	wu-ftpd
# Version required:     2.4.2-beta-18
# Date created:		18 Oct 1994
# Whom:			torstenb
#
# $Id: Makefile,v 1.2 1999/10/20 15:43:57 itojun Exp $
#
# REMINDER: to use ftpaccess(5) you need to specify -a in command line,
# it is changed from previous versions

DISTNAME=       wu-ftpd-2.5.0
CATEGORIES=	net
# AUSCERT recommendation
MASTER_SITES=   ftp://ftp.vr.net/pub/wu-ftpd/wu-ftpd/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=     wu-ftpd-250-v6-19991020.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=     ache@FreeBSD.org

do-build:
	cd ${WRKSRC} && ./build nbs

MAN1=		ftpcount.1 ftpwho.1
MAN5=		ftpaccess.5 ftphosts.5 ftpconversions.5 xferlog.5
MAN8=		ftpd.8 ftpshut.8

.include "../../mk/bsd.pkg.mk"
