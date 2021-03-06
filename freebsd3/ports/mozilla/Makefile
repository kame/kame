# New ports collection makefile for:	mozilla
# Date created:		31 Mar 1998
# Whom:			eivind/dima/jseger
#
# $FreeBSD: ports/www/mozilla/Makefile,v 1.46 2000/08/14 00:04:10 reg Exp $
#

PORTNAME=	mozilla
PORTVERSION= 	M18
CATEGORIES=	www ipv6
MASTER_SITES=	ftp://ftp.mozilla.org/pub/mozilla/releases/${PORTVERSION:S/M/m/}/src/
DISTNAME=	${PORTNAME}-source-${PORTVERSION}

MAINTAINER=	sumikawa@kame.net

LIB_DEPENDS=	gtk12.2:${PORTSDIR}/x11-toolkits/gtk12 \
		IDL.2:${PORTSDIR}/devel/ORBit

GLIB_CONFIG?=	${LOCALBASE}/bin/glib12-config
GTK_CONFIG?=	${X11BASE}/bin/gtk12-config

WRKSRC=		${WRKDIR}/${PORTNAME}

USE_BZIP2=	yes
USE_X_PREFIX=	yes
USE_PERL5=	yes
GNU_CONFIGURE=	yes
USE_GMAKE=	yes
USE_NEWGCC=	yes
CONFIGURE_ARGS=					\
		--disable-cpp-rtti		\
		--disable-debug			\
		--disable-idltool		\
		--disable-md			\
		--disable-pedantic		\
		--disable-xterm-updates		\
		--enable-cpp-exceptions		\
		--enable-double-buffer		\
		--enable-editor			\
		--enable-mailnews		\
		--enable-mathml			\
		--enable-optimize		\
		--enable-pics			\
		--enable-tests			\
		--enable-toolkit=gtk		\
		--enable-x11-shm		\
		--with-pthreads			\
		--with-jpeg=${LOCALBASE}	\
		--with-png=${LOCALBASE}
CONFIGURE_ENV=	GLIB_CONFIG="${GLIB_CONFIG}"	\
		GTK_CONFIG="${GTK_CONFIG}"
MAKE_ENV=	LD_LIBRARY_PATH=${WRKSRC}/dist/bin \
		CC_ONLY_FLAGS="${FLAGS}" CCC_ONLY_FLAGS="${CXXFLAGS}"

post-build:
	@${SED} -e "s;@PREFIX@;${PREFIX};g" \
		${FILESDIR}/mozilla.sh >${WRKSRC}/mozilla
	@${CHMOD} 555 ${WRKSRC}/mozilla
	@(cd ${WRKSRC}/dist/bin; \
	  ${ENV} LD_LIBRARY_PATH=. MOZILLA_FIVE_HOME=. ./regxpcom; \
	  ${ENV} LD_LIBRARY_PATH=. MOZILLA_FIVE_HOME=. ./regchrome)

do-install:
	${MKDIR} ${PREFIX}/lib/mozilla
	${CHMOD} 755 ${PREFIX}/lib/mozilla
	cd ${WRKSRC}/dist/bin && ${TAR} -chf - * | \
		${TAR} -xf - -C ${PREFIX}/lib/mozilla
	${INSTALL_SCRIPT} ${WRKSRC}/mozilla ${PREFIX}/bin

.include <bsd.port.mk>
