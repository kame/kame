# New ports collection makefile for:	socks64
# Version required:			v1.0r8-19990118
# Date created:				24 Apr 1996
# Whom:					pst
#
# $Id: Makefile,v 1.2 1999/12/28 04:34:52 sumikawa Exp $
#

DISTNAME=	socks5-v1.0r8
PKGNAME=	socks64-1.0.8.19990118
CATEGORIES=	net security
MASTER_SITES=	ftp://ftp.kame.net/pub/kame/misc/
DISTFILES=	${DISTNAME}${EXTRACT_SUFX} ${SOCKS64}.tgz

PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@kame.net

NO_CDROM=	"NEC has a funky license for this software"
RESTRICTED=	"no commercial use"

SOCKS64=	socks64-v10r8-19990118

# here are some extra configure args you may wish to use
# see the readme file before screwing with them
#
#EXTRA_CONFIGURE_ARGS= \
#		--with-default-server=socks.mydomain.com \
#		--with-syslog-facility=LOG_AUTH \
#		--with-passwd

WRKSRC=		${WRKDIR}/${DISTNAME}
GNU_CONFIGURE=	yes
CONFIGURE_ARGS=	--with-libconffile=${PREFIX}/etc/libsocks5.conf \
		--with-srvconffile=${PREFIX}/etc/socks5.conf \
		--with-srvpidfile=/var/run/socks5.pid \
		--with-srvidtfile=/var/run/socks5.ident \
		--enable-ipv6 \
		${EXTRA_CONFIGURE_ARGS}
MAN1=		runsocks.1 socks5.1 stopsocks.1 socks5_clients.1
MAN5=		libsocks5.conf.5 socks5.conf.5

.include <bsd.port.pre.mk>

.if !exists(${DISTDIR}/${DISTNAME}${EXTRACT_SUFX})
IGNORE=		NEC requires that you grab the dist files from their \
		web site at http://www.socks.nec.com.  Please make sure \
		you have ${DISTNAME}${EXTRACT_SUFX} in ${DISTDIR} \
		and run make again.
.endif

post-patch:
	@(cd ${WRKDIR}; ${PATCH} ${PATCH_DIST_ARGS} < socks64.diff)

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

.include <bsd.port.post.mk>
