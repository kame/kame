# New ports collection makefile for:	leafnode+
# Date created:		19 November 1998
# Whom:			Tom Hukins <tom@FreeBSD.org>
#
# $FreeBSD: ports/news/leafnode+/Makefile,v 1.15 2000/04/09 17:33:01 cpiazza Exp $
#

PORTNAME=	leafnode+
PORTVERSION=	2.10
CATEGORIES=	news
MASTER_SITES=	ftp://hiroshima.isdn.uiuc.edu/leafnode+/

PATCH_SITES=	ftp://ftp2.v6.linux.or.jp/pub/Linux/IPv6-2/leafnode+/
PATCHFILES=	leafnode+-2.10-v6-20000111.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	sumikawa@kame.net

MAN8=		checkgroups.8 fetchnews.8 leafnode.8 texpire.8
PKGINSTALL=	${WRKDIR}/INSTALL

.if defined(NOPORTDOCS)
PLIST=	${PKGDIR}/PLIST.nodocs
.endif

LEAFLIBDIR?=	${PREFIX}/lib/leafnode
LEAFSPOOLDIR?=	/var/spool/leafnode
REWRITE=	${SED} -e "s:@LIBDIR@:${LEAFLIBDIR}:g" \
		-e "s:@SPOOLDIR@:${LEAFSPOOLDIR}:g" \
		-e "s:@PREFIX@:${PREFIX}:g"

post-patch:
.for file in Makefile FAQ INSTALL README leafnode.8
	@${MV} ${WRKSRC}/${file} ${WRKSRC}/${file}.bak
	@${REWRITE} ${WRKSRC}/${file}.bak > ${WRKSRC}/${file}
.endfor
	@${REWRITE} ${FILESDIR}/INSTALL.in > ${PKGINSTALL}
	@${CHMOD} 755 ${PKGINSTALL}

do-install:
.for file in leafnode fetchnews texpire checkgroups leaftool
	@${INSTALL_PROGRAM} ${WRKSRC}/${file} ${PREFIX}/sbin
.endfor
.for file in ${MAN8}
	@${INSTALL_MAN} ${WRKSRC}/${file} ${PREFIX}/man/man8
.endfor
.if !defined{NOPORTDOCS}
	@${ECHO} "===>  Copying documents to ${PREFIX}/share/doc/leafnode+"
	@${MKDIR} ${PREFIX}/share/doc/leafnode+
.for file in Changes FAQ INSTALL README config.example
	@${INSTALL_DATA} ${WRKSRC}/${file} ${PREFIX}/share/doc/leafnode+
.endfor
.endif

post-install:
	@PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL

.include <bsd.port.mk>
