# New ports collection makefile for:   ethereal
# Version required:    0.5.0
# Date created:        10 August 1998
# Whom:                Bill Fumerola <billf@chc-chimes.com>
#
# $Id: Makefile,v 1.1.1.1 1999/08/17 09:09:31 itojun Exp $
#

DISTNAME=	ethereal-0.6.3
CATEGORIES=	net
MASTER_SITES=	ftp://ethereal.zing.org/pub/ethereal/

MAINTAINER=	itojun@kame.net

LIB_DEPENDS=	gtk12.1:${PORTSDIR}/x11-toolkits/gtk12

USE_X_PREFIX=	yes
GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	CPPFLAGS=-I${.CURDIR}/../../src/libpcap \
		LIBS="-L${.CURDIR}/../../src/libpcap -L/usr/local/v6/lib" \
		GTK_CONFIG=${X11BASE}/bin/gtk12-config

MAN1= ethereal.1

.include <bsd.port.mk>
