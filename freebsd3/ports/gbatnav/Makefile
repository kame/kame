# Ports collection Makefile for:	gbatnav
# Date created:				Sun Jun 25 17:58:17 JST 2000
# Whom:					sumikawa
#
# $KAME: Makefile,v 1.4 2000/06/27 09:15:13 sumikawa Exp $
#

PORTNAME=	gbatnav
PORTVERSION=	0.74.0
CATEGORIES=	games gnome ipv6
MASTER_SITES=	http://download.sourceforge.net/batnav/

MAINTAINER=	sumikawa@kame.net

RUN_DEPENDS=	gnomecc:${PORTSDIR}/sysutils/gnomecontrolcenter

GTK_CONFIG?=	${X11BASE}/bin/gtk12-config

GNU_CONFIGURE=	YES
CONFIGURE_ENV=	GTK_CONFIG="${GTK_CONFIG}" \
		CPPFLAGS="-I${LOCALBASE}/include" \
		LDFLAGS="-L/usr/local/v6/lib -L${LOCALBASE}/lib" \
		LIBS="-linet6"
CONFIGURE_ARGS=	--datadir=${PREFIX}/share/gnome

.include <bsd.port.mk>
