# New ports collection makefile for:    irc
# Version required:     1.0
# Date created:         26 Jul 1999
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.3 1999/12/08 02:48:50 itojun Exp $
#

DISTNAME=	irc2.10.2p1
PKGNAME=	irc-2.10.2p1
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.funet.fi/pub/unix/irc/server/
EXTRACT_SUFX=	.tgz

MAINTAINER=	sumikawa@kame.net

BROKEN=		"uses non-standard struct field"

GNU_CONFIGURE=  yes
CONFIGURE_ARGS= --enable-ip6 --without-ncurses

MAN1=		irc.1
MAN5=		iauth.conf.5
MAN8=		ircd.8 iauth.8 ircdwatch.8

do-build:
	@(cd ${WRKSRC}/${MACHINE_ARCH}-unknown-netbsd1.4.1; ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} ${ALL_TARGET})

do-install:
	@(cd ${WRKSRC}/${MACHINE_ARCH}-unknown-netbsd1.4.1 && ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} ${INSTALL_TARGET})

.include "../../mk/bsd.pkg.mk"
