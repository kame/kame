# New ports collection makefile for:	mediator
# Version required:	19990507
# Date created:		Thu Apr 15 16:28:43 JST 1999
# Whom:			Jun-ichiro itojun Hagino
#
# $Id: Makefile,v 1.1 1999/08/17 09:10:02 itojun Exp $
#

DISTNAME=	mediator-SNAP-19990507
PKGNAME=	mediator-19990507
CATEGORIES=	net

MAINTAINER=	itojun@kame.net

RESTRICTED=	"original package redistribution prohibited"

GNU_CONFIGURE=	yes
CONFIGURE_ENV=	INSTALL_PROGRAM="${INSTALL_SCRIPT}"

do-fetch:
	@if test \! -f ${DISTDIR}/${DISTNAME}${EXTRACT_SUFX}; then \
		${ECHO_MSG} "===> You need to fetch the original tar.gz by your own, into ${DISTDIR}."; \
		${ECHO_MSG} "     (redistribution restricted and the URL is not made public)"; \
		exit 1; \
	fi

.include <bsd.port.mk>
