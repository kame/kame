# Ports collection Makefile for:	
# Date created:				
# Whom:					
#
# $FreeBSD$
#

#PORTNAME=		gbatnav
#PORTVERSION=		0.74.0
DISTNAME=		gbatnav-0.74.0
CATEGORIES=		games gnome
MASTER_SITES=		http://download.sourceforge.net/batnav/

MAINTAINER=		sumikawa@kame.net

LIB_DEPENDS=		panel_applet.4:${PORTSDIR}/x11/gnomecore

GTK_CONFIG?=		${X11BASE}/bin/gtk12-config

#USE_X_PREFIX=		YES
#USE_BZIP2=		YES
GNU_CONFIGURE=		YES
CONFIGURE_ENV=		GTK_CONFIG="${GTK_CONFIG}" \
			CPPFLAGS="-I${LOCALBASE}/include" \
			LIBS="-L${LOCALBASE}/lib"
CONFIGURE_ARGS=		--datadir=${PREFIX}/share/gnome

.include <bsd.port.mk>
