# New ports collection makefile for:    XFree86
# Date created:         5 January 1995
# Whom:                 jmz
#
# $FreeBSD: ports/x11/XFree86-4/Makefile,v 1.145 2002/03/18 16:43:49 will Exp $
#

PORTNAME=	XFree86
PORTVERSION=	4.2.0
PORTREVISION=	1
PORTEPOCH=	1
CATEGORIES=	x11 ipv6
MASTER_SITES=	# none
DISTFILES=	# none
EXTRACT_ONLY=	# none

LIB_DEPENDS=	Xft.1:${PORTSDIR}/x11/XFree86-4-libraries+ipv6
RUN_DEPENDS=	xvinfo:${PORTSDIR}/x11/XFree86-4-clients+ipv6 \
	${X11BASE}/lib/X11/doc/ddx.TXT:${PORTSDIR}/x11/XFree86-4-documents \
	${FONT100DPI}:${PORTSDIR}/x11-fonts/XFree86-4-font100dpi \
	${FONT75DPI}:${PORTSDIR}/x11-fonts/XFree86-4-font75dpi \
	${FONTCYR}:${PORTSDIR}/x11-fonts/XFree86-4-fontCyrillic \
	${FONTDEFAULT}:${PORTSDIR}/x11-fonts/XFree86-4-fontDefaultBitmaps \
	${FONTSCALE}:${PORTSDIR}/x11-fonts/XFree86-4-fontScalable \
	${X11BASE}/bin/xfs:${PORTSDIR}/x11-servers/XFree86-4-FontServer \
	${X11BASE}/bin/xf86cfg:${PORTSDIR}/x11-servers/XFree86-4-Server+ipv6

MAINTAINER=	jmz@FreeBSD.org

NO_BUILD=	yes
LATEST_LINK=	XFree86-4
FONT100DPI=	${X11BASE}/lib/X11/fonts/100dpi/UTBI__10-ISO8859-1.pcf.gz
FONT75DPI=	${X11BASE}/lib/X11/fonts/75dpi/UTBI__10-ISO8859-1.pcf.gz
FONTCYR=	${X11BASE}/lib/X11/fonts/cyrillic/crox1c.pcf.gz
FONTDEFAULT=	${X11BASE}/lib/X11/fonts/misc/cursor.pcf.gz
FONTSCALE=	${X11BASE}/lib/X11/fonts/PEX/Roman.phont

do-install:	# empty

.include <bsd.port.mk>
