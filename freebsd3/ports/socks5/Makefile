# New ports collection makefile for:	socks5
# Version required:			v1.0r10-trans-v1.3
# Date created:				Fri Nov 26 10:41:04 JST 1999
# Whom:					sumikawa
#
# $Id: Makefile,v 1.1 1999/11/30 12:52:27 sumikawa Exp $
#

DISTNAME=	socks5-v1.0r10
PKGNAME=	socks5-v1.0r10-trans-v1.3
CATEGORIES=	net security
MASTER_SITES=	ftp://ftp.kame.net/pub/kame/misc/

PATCHFILES=	socks-trans-v1.3-patch.gz
PATCH_DIST_STRIP=	-p

MAINTAINER=	sumikawa@kame.net

NO_CDROM=	"NEC has a funky license for this software"
RESTRICTED=	"no commercial use"

# here are some extra configure args you may wish to use
# see the readme file before screwing with them
#
#EXTRA_CONFIGURE_ARGS= \
#		--with-default-server=socks.mydomain.com \
#		--with-syslog-facility=LOG_AUTH \
#		--with-passwd

WRKSRC=		${WRKDIR}/${DISTNAME}
GNU_CONFIGURE=	yes
USE_AUTOCONF=	yes
CONFIGURE_ARGS=	--with-libconffile=${PREFIX}/etc/libsocks5.conf \
		--with-srvconffile=${PREFIX}/etc/socks5.conf \
		--with-srvpidfile=/var/run/socks5.pid \
		--with-srvidtfile=/var/run/socks5.ident \
		--enable-ipv6 \
		${EXTRA_CONFIGURE_ARGS}
EXTRA_LDFLAGS=	-L/usr/local/v6/lib -linet6
MAN1=		socks5.1 stopsocks.1 socks5_clients.1
MAN5=		libsocks5.conf.5 socks5.conf.5

pre-fetch:
	@if [ ! -f ${DISTDIR}/${DISTNAME}${EXTRACT_SUFX} ]; then \
	  ${ECHO} ""; \
	  ${ECHO} "NEC requires that you grab the dist files from their"; \
	  ${ECHO} "web site at http://www.socks.nec.com.  Please make sure"; \
	  ${ECHO} "you have ${DISTNAME}${EXTRACT_SUFX} in ${DISTDIR}"; \
	  ${ECHO} "and run make again."; \
	  ${ECHO} ""; \
	  exit 1;\
	fi
	@if [ ! -f ${DISTDIR}/${PATCHFILES} ]; then \
	  ${ECHO} ""; \
	  ${ECHO} "NEC requires that you grab the dist files from their"; \
	  ${ECHO} "web site at http://www.socks.nec.com.  Please make sure"; \
	  ${ECHO} "you have ${PATCHFILES} in ${DISTDIR}"; \
	  ${ECHO} "and run make again."; \
	  ${ECHO} ""; \
	  exit 1;\
	fi

.include <bsd.port.mk>

# the following need to be included after bsd.port.mk, since OPSYS
# ARCH are defined in bsd.port.mk

.if ${OPSYS} == "FreeBSD"
CONFIGURE_ENV=  LIBS=-lcrypt
.endif

# OpenBSD/arc doesn't seem to have a working ldconfig

.if ${OPSYS} != "OpenBSD" || ${ARCH} != "arc"
post-install:
	ldconfig -m ${PREFIX}/lib
.endif
