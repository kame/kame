# $NetBSD: Makefile,v 1.13 1998/08/20 15:17:20 tsarna Exp $
# FreeBSD Id: Makefile,v 1.14 1997/08/28 06:49:06 obrien Exp
#

DISTNAME=	socks5-v1.0r8
PKGNAME=	socks64-1.0.8.19990118
CATEGORIES=	net security
MASTER_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
DISTFILES=	${DISTNAME}${EXTRACT_SUFX} ${SOCKS64}.tgz

MAINTAINER=	itojun@kame.net
HOMEPAGE=	http://www.socks.nec.com/

CONFLICTS=	socks4-2.2

NO_CDROM=	"NEC has a funky license for this software"
RESTRICTED=	"no commercial use"

SOCKS64=	socks64-v10r8-19990118
PATCH_DIST_STRIP=	-p1

# here are some extra configure args you may wish to use
# see the readme file before screwing with them
#
#EXTRA_CONFIGURE_ARGS+= \
#		--with-default-server=socks.mydomain.com \
#		--with-syslog-facility=LOG_AUTH \
#		--with-passwd

WRKSRC=		${WRKDIR}/${DISTNAME}
GNU_CONFIGURE=	yes
CONFIGURE_ENV+=  LIBS=-lcrypt
CONFIGURE_ARGS=	--with-libconffile=${PREFIX}/etc/libsocks5.conf \
		--with-srvconffile=${PREFIX}/etc/socks5.conf \
		--with-srvpidfile=/var/run/socks5.pid \
		--with-srvidtfile=/var/run/socks5.ident \
		--enable-ipv6 \
		${EXTRA_CONFIGURE_ARGS}

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

post-patch:
	@(cd ${WRKDIR}; ${PATCH} ${PATCH_DIST_ARGS} < socks64.diff)

post-install:
	${LN} -fs ${PREFIX}/lib/libsocks5_sh.so ${PREFIX}/lib/libsocks5_sh.so.0.0

.include "../../mk/bsd.pkg.mk"

# this is to override CONFIGURE_ENV settings in bsd.pkg.mk.
# I believe this is odd to have "-Wl" prefix in LDFLAGS...
CONFIGURE_ENV+=	LDFLAGS=-R${PREFIX}/lib
