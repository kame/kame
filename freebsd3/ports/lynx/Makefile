# New ports collection makefile for:    lynx
# Date created:         15 Dec 1994
# Whom:                 ache
#
# $FreeBSD: ports/www/lynx/Makefile,v 1.88 1999/08/31 06:51:50 mharo Exp $
#

PORTNAME=	lynx2.8.2
PORTVERSION=	rel.1
CATEGORIES=	www
MASTER_SITES=   http://lynx.isc.org/current/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	lynx-282-v6-20000201.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	k-sugyou@kame.net

BROKEN=		"security issues"

USE_BZIP2=      YES
WRKSRC=         ${WRKDIR}/lynx2-8-2
GNU_CONFIGURE=  YES
CONFIGURE_ARGS= --with-screen=ncurses --with-zlib --libdir="${L_LIB}" \
		--enable-nsl-fork --enable-persistent-cookies
MAKE_FLAGS=     helpdir=${L_HELP} -f
MAKEFILE=       makefile
INSTALL_TARGET= install install-help
MAN1=		lynx.1

L_LIB=          ${PREFIX}/etc
L_HELP=         ${PREFIX}/share/lynx_help

post-install:
	${CHOWN} -R ${SHAREOWN}:${SHAREGRP} ${L_HELP}
	${CHOWN} ${SHAREOWN}:${SHAREGRP} ${L_LIB}/lynx.cfg

.include <bsd.port.mk>
