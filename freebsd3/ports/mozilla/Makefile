# New ports collection makefile for:	mozilla
# Version required:	1998-07-28
# Date created:		5 Oct 1998
# Whom:			k-sugyo/shin
#
# $Id: Makefile,v 1.1.1.1 1999/08/17 09:10:04 itojun Exp $
#

DISTNAME=	mozilla-19980728
PKGNAME=	mozilla-kame-19980728
CATEGORIES=	www
MASTER_SITES=	ftp://ftp.kame.net/pub/kame/misc/
# .jp
MASTER_SITES+=	ftp://ftp.cin.nihon-u.ac.jp/pub/Mozilla/mozilla/source/
MASTER_SITES+=	ftp://mirror.neosoft.com/pub/mozilla/mozilla/source/ \
		ftp://ftp.bitcon.no/pub/www/mozilla/mozilla/source/ \
		ftp://ftp.mozilla.org/pub/mozilla/source/
DISTFILES=	mozilla-19980728.tar.gz ipv6-anim-mozilla-19980603.tar.gz

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	mozilla-19980728-kame-patch_at_19981002.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	jseger@FreeBSD.org

WRKSRC=		${WRKDIR}/mozilla
PATCH_STRIP=	-p1
USE_GMAKE=	yes
DIST_SUBDIR=	mozilla
MAKE_ENV=	NO_SECURITY=1 MOZ_MEDIUM=1 MOZILLA_CLIENT=1 NO_MDUPDATE=1 \
		USE_IPV6=1 MOTIF_STATIC=1 \
	BUILD_OPT=1 NO_NETSCAPE_STATIC=1 LD_LIBRARY_PATH=${LOCALBASE}/lib
REQUIRES_MOTIF=	yes

OSNAME=	`uname -s`
OSVER=	`uname -r | ${SED} 's/-.*//'`
OBJDIR=	${WRKSRC}/dist/${OSNAME}${OSVER}_OPT.OBJ

do-install:
	@${MKDIR} ${PREFIX}/lib/mozilla/bin
	@cd ${OBJDIR}/bin && tar -chf - bsdecho lib* moz-export \
		nsinstall vreg | tar -xf - -C ${PREFIX}/lib/mozilla/bin
	@chmod 755 ${PREFIX}/lib/mozilla/bin
	@${INSTALL_SCRIPT} ${WRKSRC}/mozilla ${PREFIX}/bin
	@if [ ! -f ${PREFIX}/lib/mozilla/mailcap ] ; then \
		${INSTALL_DATA} ${FILESDIR}/mailcap ${PREFIX}/lib/mozilla ; \
	fi
	@strip ${PREFIX}/lib/mozilla/bin/moz-export
	@chown -R bin.bin ${PREFIX}/lib/mozilla

.include <bsd.port.mk>
