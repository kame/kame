# New ports collection makefile for:	wwwoffle
# Date created:		Thu Oct 28 13:39:54 JST 1999
# Whom:			jinmei@kame.net
#
# $KAME: Makefile,v 1.4 2000/06/25 10:58:51 sumikawa Exp $
#

PORTNAME=	wwwoffle
PORTVERSION=	2.5
CATEGORIES=	www
MASTER_SITES=	ftp://ftp.demon.co.uk/pub/unix/httpd/ \
		${MASTER_SITE_SUNSITE:=apps/www/servers/} \
		ftp://ftp.pasta.cs.uit.no/pub/Vermicelli/
DISTFILES=	wwwoffle-2.5.tgz \
		wwwoffle-2.5-patches.v6.tar.gz

MAINTAINER=	jinmei@kame.net

USE_GMAKE=	yes

PATCHDIR=       ${WRKDIR}/.patches
MESSAGE_FILE=	${WRKDIR}/MESSAGE

MAN1=		wwwoffle.1
MAN5=		wwwoffle.conf.5
MAN8=		wwwoffled.8

pre-patch:
	${MKDIR} ${PATCHDIR}
	${CP} ${.CURDIR}/patches/patch-* ${PATCHDIR}
	${CP} ${WRKDIR}/wwwoffle-2.5-patches.v6/patch-* ${PATCHDIR}

post-build:
	@${SED} -e 's#@PREFIX@#${PREFIX}#g' <${FILESDIR}/wwwoffle.sh \
	  >${WRKDIR}/wwwoffle.sh
	@${SED} -e 's#@PREFIX@#${PREFIX}#g' <${PKGDIR}/MESSAGE \
	  >${MESSAGE_FILE}
#	@${SED} -e 's#@GTAR@#${TAR}#g' <${PKGDIR}/PLIST >${PLIST_SRC}

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
