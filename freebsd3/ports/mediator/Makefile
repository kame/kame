# New ports collection makefile for:	mediator
# Version required:	19990507
# Date created:		Thu Apr 15 16:28:43 JST 1999
# Whom:			Jun-ichiro itojun Hagino
#
# $Id: Makefile,v 1.2 1999/12/08 02:05:02 sumikawa Exp $
#

DISTNAME=	mediator-SNAP-19990507
PKGNAME=	mediator-19990507
CATEGORIES=	net

MAINTAINER=	itojun@kame.net

RESTRICTED=	"original package redistribution prohibited"

GNU_CONFIGURE=	yes
CONFIGURE_ENV=	INSTALL_PROGRAM="${INSTALL_SCRIPT}"

.if !exists(${DISTDIR}/${DISTNAME}${EXTRACT_SUFX}) \
	&& !exists(${DISTDIR}/fwtk-doc-only${EXTRACT_SUFX})
IGNORE='You need to fetch ${DISTNAME}${EXTRACT_SUFX} by your own, into ${DISTDIR}. (redistribution restricted and the URL is not made public).'
.endif

.include <bsd.port.mk>
