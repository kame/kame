# Ports collection Makefile for:	gbatnav
# Date created:				Sun Jun 25 17:58:17 JST 2000
# Whom:					sumikawa
#
# $KAME: Makefile,v 1.3 2000/06/25 10:58:32 sumikawa Exp $
#

PORTNAME=		gbatnav
PORTVERSION=		0.74.0
CATEGORIES=		games gnome
MASTER_SITES=		http://download.sourceforge.net/batnav/

MAINTAINER=		sumikawa@kame.net

LIB_DEPENDS=		panel_applet.4:${PORTSDIR}/x11/gnomecore

GTK_CONFIG?=		${X11BASE}/bin/gtk12-config

GNU_CONFIGURE=		YES
CONFIGURE_ENV=		GTK_CONFIG="${GTK_CONFIG}" \
			CPPFLAGS="-I${LOCALBASE}/include" \
			LDFLAGS="-L/usr/local/v6/lib -L${LOCALBASE}/lib" \
			LIBS="-linet6"
CONFIGURE_ARGS=		--datadir=${PREFIX}/share/gnome

.include <bsd.port.mk>
