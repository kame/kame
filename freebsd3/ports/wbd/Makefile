# New ports collection makefile for:	wbd
# Version required:     1.00a
# Date created:		Wed Jan 27 21:16:38 JST 1999
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.1.1.1 1999/08/17 09:10:59 itojun Exp $
#

DISTNAME=       wbd-1.00a
CATEGORIES=	mbone tk80
MASTER_SITES=   http://bashful.lboro.ac.uk/ROPA/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	wbd-100a-v6-19990127.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@itojun.org

#LIB_DEPENDS+=	tcl80:${PORTSDIR}/lang/tcl80
LIB_DEPENDS=	tk80:${PORTSDIR}/x11-toolkits/tk80

GNU_CONFIGURE=	yes
USE_AUTOCONF=	yes
CONFIGURE_ARGS=	--enable-ipv6

ALL_TARGET=	wbd

pre-configure:
	chmod +x ${WRKSRC}/configure
	chmod +x ${WRKSRC}/config.guess
	chmod +x ${WRKSRC}/config.sub

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/wbd ${PREFIX}/bin
	${MKDIR} ${PREFIX}/share/doc/wbd
	for i in COPYRIGHT README; do \
		${INSTALL_DATA} ${WRKSRC}/$$i ${PREFIX}/share/doc/wbd; \
	done

.include <bsd.port.mk>
