# New ports collection makefile for:   ethereal
# Version required:    0.7.5
# Date created:        10 August 1998
# Whom:                Bill Fumerola <billf@chc-chimes.com>
#
# $Id: Makefile,v 1.3 1999/11/25 11:00:20 sumikawa Exp $
#

DISTNAME=	ethereal-0.7.8
CATEGORIES=	net
MASTER_SITES=	http://alpha1.linuxberg.com/files/x11/network/ \
		http://www.linuxberg.com/files/x11/network/ \
		http://jefnet.linuxberg.com/files/x11/network/ \
		http://ethereal.zing.org/distribution/ \
		http://ethereal.boehm.org/distribution/

MAINTAINER=	itojun@kame.net

LIB_DEPENDS=	gtk12.2:${PORTSDIR}/x11-toolkits/gtk12

USE_X_PREFIX=	yes
GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	CPPFLAGS=-I${.CURDIR}/../../src/libpcap \
		LIBS="-L${.CURDIR}/../../src/libpcap -L/usr/local/v6/lib" \
		GTK_CONFIG=${X11BASE}/bin/gtk12-config

MAN1=		ethereal.1

.include <bsd.port.mk>
