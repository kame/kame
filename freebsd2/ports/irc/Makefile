# New ports collection makefile for:    irc
# Version required:     1.0
# Date created:         26 Jul 1999
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.1 1999/08/09 01:37:05 itojun Exp $
#

DISTNAME=	irc2.10.2p1
PKGNAME=	irc-2.10.2p1
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.funet.fi/pub/unix/irc/server/
EXTRACT_SUFX=	.tgz

MAINTAINER=	sumikawa@kame.net

GNU_CONFIGURE=  yes
CONFIGURE_ARGS= --enable-ip6 --without-ncurses

MAN1=		irc.1
MAN5=		iauth.conf.5
MAN8=		ircd.8 iauth.8 ircdwatch.8

STARTUP_SCRIPT=	${PREFIX}/etc/rc.d/ircd.sh

do-build:
	@(cd ${WRKSRC}/${MACHINE_ARCH}-unknown-freebsd${OSREL}; ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} ${ALL_TARGET})

do-install:
	@(cd ${WRKSRC}/${MACHINE_ARCH}-unknown-freebsd${OSREL} && ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} ${INSTALL_TARGET})

post-install:
	@if [ ! -f ${STARTUP_SCRIPT} ]; then				\
		echo "Installing ${STARTUP_SCRIPT} startup file.";	\
		echo '#!/bin/sh' > ${STARTUP_SCRIPT};			\
		echo "[ -f ${PREFIX}/lib/ircd/ircd.conf ] && ${PREFIX}/sbin/ircd -b -c && echo -n ' ircd'" >> ${STARTUP_SCRIPT} ;	\
		chmod 755 ${STARTUP_SCRIPT} ;				\
		chown bin.bin ${STARTUP_SCRIPT};			\
	fi

.include <bsd.port.mk>
