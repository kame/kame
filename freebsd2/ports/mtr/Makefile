# New ports collection makefile for:   mtr
# Version required:    0.28
# Date created:        12 August 1998
# Whom:                Bill Fumerola <billf@chc-chimes.com>
#
# $FreeBSD$
#

DISTNAME=	mtr-0.42
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.bitwizard.nl/mtr/ \
		http://www.giovannelli.it/~gmarco/files/

PATCHFILES=	mtr-042-v6-20000506.diff.gz
PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@kame.net

USE_GMAKE=	yes
GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--enable-ipv6

MAN8=	mtr.8

pre-patch:
.if !defined(USE_GTK)
	@${ECHO} ""
	@${ECHO} "If you want to compile with GTK support,"
	@${ECHO} "hit Ctrl-C right now and use \"make USE_GTK=yes\" "
	@${ECHO} ""
CONFIGURE_ARGS+=--with-gtk-prefix=/nopath
.else
USE_XLIB=	yes
LIB_DEPENDS=    gtk12.2:${PORTSDIR}/x11-toolkits/gtk12
CONFIGURE_ENV=	GTK_CONFIG="${X11BASE}/bin/gtk12-config"
.endif

do-install:
	${INSTALL} -c -s -m 4755 -o root -g wheel ${WRKSRC}/mtr ${PREFIX}/sbin
	${INSTALL_DATA} ${WRKSRC}/mtr.8 ${PREFIX}/man/man8

post-install:
	@${ECHO} ""
	@${ECHO} "${PREFIX}/sbin/mtr is setuid \"root\" "
	@${ECHO} ""
	@${ECHO} "Please read about potential security iussues"
	@${ECHO} "in file ${WRKSRC}/SECURITY (not installed)"
	@${ECHO} ""

.include <bsd.port.mk>
