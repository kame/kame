# New ports collection makefile for:    kaffe
# Version required:     1.0.b1
# Date created:         20 February 1995
# Whom:                 Tim Wilkinson <tim@sarc.city.ac.uk>
#
# $Id: Makefile,v 1.2 1999/12/27 12:37:09 sumikawa Exp $
#

DISTNAME=	kaffe-1.0.b1
CATEGORIES=	lang
MASTER_SITES=	ftp://ftp.transvirtual.com/pub/kaffe/ \
		ftp://ftp.kame.net/pub/inria/freebsd/ \
		ftp://ftp.v6.kame.net/pub/inria/freebsd/ \
		ftp://ftp.inria.fr/network/ipv6/freebsd/
EXTRACT_ONLY=	${DISTNAME}${EXTRACT_SUFX}
DISTFILES=	${DISTNAME}${EXTRACT_SUFX} ${V6FIX}

PATCH_ARGS=	-d ${WRKDIR} --forward --quiet -E ${PATCH_STRIP}

BROKEN=		"not working right yet"
IS_INTERACTIVE=	"funky two phase build requilred"

MAINTAINER=	itojun@kame.net

LIB_DEPENDS=	jpeg.9:${PORTSDIR}/graphics/jpeg \
		gif.5:${PORTSDIR}/graphics/giflib \
		png.3:${PORTSDIR}/graphics/png
BUILD_DEPENDS=	zip:${PORTSDIR}/archivers/zip

WRKSRC=		${WRKDIR}/kaffe-1.0.b1
GNU_CONFIGURE=	yes
MAN1=		kaffe.1

V6FIX=		New.tar.gz
V6FIXPATH=	usr/src/local/kaffe-1.0.b1
V6FILE1=	libraries/clib/awt/Makefile.in \
		libraries/javalib/Makefile.in
V6FILE2=	libraries/clib/net/InetAddress.h \
		libraries/clib/net/InetAddressImpl.c \
		libraries/clib/net/InetAddressImpl.h \
		libraries/clib/net/PlainDatagramSocketImpl.c \
		libraries/clib/net/PlainDatagramSocketImpl.h \
		libraries/clib/net/PlainSocketImpl.c \
		libraries/clib/awt/Makefile.in \
		libraries/javalib/java/net/DatagramSocketImpl.java \
		libraries/javalib/java/net/InetAddress.java \
		libraries/javalib/java/net/InetAddressImpl.java \
		libraries/javalib/java/net/MulticastSocket.java \
		libraries/javalib/java/net/PlainDatagramSocketImpl.java \
		libraries/javalib/Makefile.in
JAVALIBPATH=	libraries/javalib

post-extract:
	(cd ${WRKDIR}; tar zxf ${DISTDIR}/${V6FIX} ${V6FIXPATH})

post-patch:
	${MAKE} v6patch1

v6patch1:
	for i in ${V6FILE2}; do \
		cp ${WRKDIR}/${V6FIXPATH}/$$i-new ${WRKSRC}/$$i; \
	done

post-install:
	${INSTALL_SCRIPT} ${WRKSRC}/ENVIRONMENT ${PREFIX}/share/kaffe
	${INSTALL_DATA} ${WRKSRC}/license.terms ${PREFIX}/share/kaffe
	${ECHO_MSG} "*** You'll need to do make v6patch build2 install2".

v6patch2:
	for i in ${V6FILE2}; do \
		cp ${WRKDIR}/${V6FIXPATH}/$$i-new ${WRKSRC}/$$i; \
	done

build2:
.if defined(USE_GMAKE)
	@(cd ${WRKSRC}; ${SETENV} ${MAKE_ENV} ${GMAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} ${ALL_TARGET})
	@(cd ${WRKSRC}/${JAVALIBPATH}; ${SETENV} ${MAKE_ENV} ${GMAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} classes build-classes)
.else defined(USE_GMAKE)
	@(cd ${WRKSRC}; ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} ${ALL_TARGET})
	@(cd ${WRKSRC}/${JAVALIBPATH}; ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} classes build-classes)
.endif

install2::
	${ECHO_MSG} "*** NOT YET".

.include <bsd.port.mk>
