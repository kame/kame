# New ports collection makefile for:   ipv6socket_scrub
# Version required:    1.0
# Date created:        Thu Nov 25 17:38:35 JST 1999
# Whom:                sumikawa@kame.net
#
# $FreeBSD$
#

DISTNAME=		IPv6socket_scrub
PKGNAME=		ipv6socket_scrub-1.0
CATEGORIES=		devel
# need to fetch on your own
MASTER_SITES=		
EXTRACT_SUFX=		.tar

MAINTAINER=		sumikawa@kame.net
HOMEPAGE=		http://www.sun.com/solaris/ipv6/

EXTRACT_CMD=            ${TAR}
EXTRACT_BEFORE_ARGS=    -xf
EXTRACT_AFTER_ARGS=     # empty

WRKSRC=			${WRKDIR}/${DISTNAME}/src
NO_CDROM=		"not redistributable"
NO_PACKAGE=		"not redistributable"
RESTRICTED=		"not redistributable, license agreement required"

.include <bsd.port.pre.mk>

.if !exists(${DISTDIR}/${DISTNAME}${EXTRACT_SUFX})
IGNORE=		You need to sign the agreement on ${HOMEPAGE} and fetch on your own,\
		and move it to ${DISTDIR} and then restart this build.
.endif

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/ipv6socket_scrub ${PREFIX}/bin
	${INSTALL_MAN} ${WRKSRC}/../Docs/man/man1/ipv6socket_scrub.1 \
		${PREFIX}/man/man1

.include <bsd.port.post.mk>
