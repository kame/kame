# $NetBSD: Makefile,v 1.18 1999/04/13 15:31:06 agc Exp $
#

DISTNAME=	rsync-2.3.2
CATEGORIES=	net
MASTER_SITES=	ftp://rsync.samba.org/pub/rsync/old-versions/ \
		ftp://sunsite.auc.dk/pub/unix/rsync/  \
		ftp://ftp.sunet.se/pub/unix/admin/rsync/  \
		ftp://ftp.fu-berlin.de/pub/unix/network/rsync/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	rsync-232-v6-20000127a.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=     itojun@itojun.org
HOMEPAGE=	http://samba.anu.edu.au/rsync/

GNU_CONFIGURE=	yes

post-install:
	@strip ${PREFIX}/bin/rsync
	@${MKDIR} ${PREFIX}/share/doc/rsync
	${INSTALL_DATA} ${WRKSRC}/tech_report.tex ${PREFIX}/share/doc/rsync

.include "../../mk/bsd.pkg.mk"
