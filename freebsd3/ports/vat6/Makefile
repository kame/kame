# New ports collection makefile for:	vat6
# Version required:	19981109
# Date created:		Fri Jul 10 17:29:13 JST 1998
# Whom:			itojun
#
# $Id: Makefile,v 1.3 1999/12/27 12:37:20 sumikawa Exp $
#

DISTNAME=	vat6
PKGNAME=	vat6-19981109
CATEGORIES=	mbone tk82
MASTER_SITES=	http://irl.cs.ucla.edu/software/IPv6/ \
		ftp://ftp.cs.tu-berlin.de/pub/local/kbs/tubmik/gsm/
DISTFILES=	${DISTNAME}${EXTRACT_SUFX} ${GSM}${EXTRACT_SUFX}

PATCH_SITES=	http://www.v6.csi2.net/setup/mcast/patch/
PATCHFILES=	vat6-kame-19990420.patch
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@itojun.org

LIB_DEPENDS=	tk82.1:${PORTSDIR}/x11-toolkits/tk82 \
		gsm.1:${PORTSDIR}/audio/gsm

USE_X11=	yes
USE_AUTOCONF=	yes
CONFIGURE_ARGS=	--with-gsm=${WRKDIR}/${GSMDIR}
CONFIGURE_ENV=	CFLAGS="-DINET6" V_LIB_V6="-L/usr/local/v6/lib -linet6"
INSTALL_TARGET=	install install-man
MAN1=		vat.1

GSM=	gsm-1.0.10
GSMDIR=	gsm-1.0-pl10

post-install:
	strip ${PREFIX}/bin/vat

.include <bsd.port.mk>
