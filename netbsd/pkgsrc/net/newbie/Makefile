# New ports collection makefile for:    newbie
# Version required:     0.22
# Date created:         6 May 1998
# Whom:                 itojun@itojun.org
# Modified by:		doi@sfc.wide.ad.jp	(1999/08/16)
#
# $Id: Makefile,v 1.1.2.1 1999/10/12 05:39:52 itojun Exp $
#

DISTNAME=       newbie-0.22
PKGNAME=	newbie-0.22
CATEGORIES=	net
MASTER_SITES=   http://www.sfc.wide.ad.jp/~doi/softs/newbie/

MAINTAINER=     itojun@itojun.org

BROKEN=		"uses nonstandard struct field"

PATCH_DIST_ARGS=	-d ${WRKSRC}/.. -E ${PATCH_DIST_STRIP}
.if !defined(PATCH_DEBUG)
PATCH_DIST_ARGS+=	--forward --quiet
.endif

RESTRICTED=	"alpha test period, no redistribution allowed"
WRKSRC=		${WRKDIR}/${DISTNAME}/src
ALL_TARGET=	default

GNU_CONFIGURE=	yes
USE_AUTOCONF=	yes

HTDOCS=	aaaa-L.gif contrib.html copyrights.txt features-j.html \
	features.html guide.html index-j.html index.html \
	install-j.html install.html libnewres.html ncl.html \
	nconsole.html newbie.html newkey.html template-j.html \
	template.html todo.html whatisnew.html zone2db.html
SAMPLE=	newbie.boot res_core.conf root.cache

do-install:
	for i in newbie cnameupd zone2db nconsole ncl nsdump newkey; do \
		${INSTALL_PROGRAM} ${WRKSRC}/$$i ${PREFIX}/sbin; \
	done
	for i in newbie.kill; do \
		${INSTALL_SCRIPT} ${WRKSRC}/$$i ${PREFIX}/sbin; \
	done
	for i in libnewres.a; do \
		${INSTALL_DATA} ${WRKSRC}/$$i ${PREFIX}/lib; \
	done
.if !defined(NOPORTDOCS)
	${MKDIR} ${PREFIX}/share/doc/newbie
	${MKDIR} ${PREFIX}/share/doc/newbie/html
	${MKDIR} ${PREFIX}/share/doc/newbie/sample
	for i in ${HTDOCS}; do \
		${INSTALL_DATA} ${WRKSRC}/../docs/html/$$i ${PREFIX}/share/doc/newbie/html; \
	done
	for i in ${SAMPLE}; do \
		${INSTALL_DATA} ${WRKSRC}/../sample/$$i ${PREFIX}/share/doc/newbie/sample; \
	done
	@${SED} -e "s#/usr/local#${PREFIX}#" ${PKGDIR}/MESSAGE
.endif

.include "../../mk/bsd.pkg.mk"
