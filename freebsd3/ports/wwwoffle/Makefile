# $Id: Makefile,v 1.1 1999/10/28 04:47:41 jinmei Exp $

DISTNAME=	wwwoffle-2.5
CATEGORIES=	www
MASTER_SITES=	ftp://ftp.demon.co.uk/pub/unix/httpd/ \
		${MASTER_SITE_SUNSITE:=apps/www/servers/}
EXTRACT_SUFX=	.tgz
DISTFILES+=	wwwoffle-2.5.tgz

MAINTAINER=	packages@netbsd.org
HOMEPAGE=	http://www.gedanken.demon.co.uk/wwwoffle/

USE_GMAKE=	yes

MESSAGE_FILE=	${WRKDIR}/MESSAGE
PLIST_SRC=	${WRKDIR}/PLIST

CHOWN=		/usr/sbin/chown
GTAR=		/usr/bin/tar

# IPv6 support
PATCHDIR=       ${WRKDIR}/.patches
MASTER_SITES+=	ftp://ftp.pasta.cs.uit.no/pub/Vermicelli/
DISTFILES+=	wwwoffle-2.5-patches.v6.tar.gz 

pre-patch:
	${MKDIR} ${WRKDIR}/.patches
	${CP} ${.CURDIR}/patches/patch-* ${WRKDIR}/.patches
	${CP} ${WRKDIR}/wwwoffle-2.5-patches.v6/patch-* ${WRKDIR}/.patches

post-build:
	@${SED} -e 's#@PREFIX@#${PREFIX}#g' <${FILESDIR}/wwwoffle.sh \
	  >${WRKDIR}/wwwoffle.sh
	@${SED} -e 's#@PREFIX@#${PREFIX}#g' <${PKGDIR}/MESSAGE \
	  >${MESSAGE_FILE}
	@${SED} -e 's#@GTAR@#${GTAR}#g' <${PKGDIR}/PLIST >${PLIST_SRC}

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
