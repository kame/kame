# New ports collection makefile for:	wwwoffle
# Version required:	2.5
# Date created:		Thu Oct 28 13:39:54 JST 1999
# Whom:			jinmei@kame.net
#
# $Id: Makefile,v 1.2 1999/10/28 05:11:24 sumikawa Exp $
#

DISTNAME=	wwwoffle-2.5
CATEGORIES=	www
MASTER_SITES=	ftp://ftp.demon.co.uk/pub/unix/httpd/ \
		${MASTER_SITE_SUNSITE:=apps/www/servers/}
EXTRACT_SUFX=	.tgz
DISTFILES=	wwwoffle-2.5.tgz

PATCHDIR=       ${WRKDIR}/.patches
DIST_SITES+=	ftp://ftp.pasta.cs.uit.no/pub/Vermicelli/
DISTFILES+=	wwwoffle-2.5-patches.v6.tar.gz

MAINTAINER=	jinmei@kame.net

USE_GMAKE=	yes

MESSAGE_FILE=	${WRKDIR}/MESSAGE

MAN1=		wwwoffle.1
MAN5=		wwwoffle.conf.5
MAN8=		wwwoffled.8

pre-patch:
	${MKDIR} ${WRKDIR}/.patches
	${CP} ${.CURDIR}/patches/patch-* ${WRKDIR}/.patches
	${CP} ${WRKDIR}/wwwoffle-2.5-patches.v6/patch-* ${WRKDIR}/.patches

post-build:
	@${SED} -e 's#@PREFIX@#${PREFIX}#g' <${FILESDIR}/wwwoffle.sh \
	  >${WRKDIR}/wwwoffle.sh
	@${SED} -e 's#@PREFIX@#${PREFIX}#g' <${PKGDIR}/MESSAGE \
	  >${MESSAGE_FILE}

pre-install:
	${MKDIR} ${PREFIX}/etc/wwwoffle

post-install:
	if [ -f ${PREFIX}/etc/wwwoffle/wwwoffle.conf.install ]; then \
	  ${MV} ${PREFIX}/etc/wwwoffle/wwwoffle.conf.install \
		${PREFIX}/etc/wwwoffle/wwwoffle.conf.default; \
	else \
	  ${CP} -p ${PREFIX}/etc/wwwoffle/wwwoffle.conf \
	    ${PREFIX}/etc/wwwoffle/wwwoffle.conf.default; \
	fi
	${INSTALL_SCRIPT} ${WRKDIR}/wwwoffle.sh ${PREFIX}/etc/rc.d
	${CHOWN} -R ${BINOWN}:${BINGRP} /var/wwwoffle

.include <bsd.port.mk>
