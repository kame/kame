# New ports collection makefile for:    tcpd6
# Version required:     	980106
# Date created:         28 Jan 1998
# Whom:                 itojun@itojun.org
#
# $Id: Makefile,v 1.1.1.1 1999/08/17 09:10:44 itojun Exp $
#

DISTNAME=       tcpd-v6-0.0-980106
PKGNAME=	tcpd6-980106
CATEGORIES=     net
MASTER_SITES=   http://www.rcac.tdi.co.jp/fujiwara/

MAINTAINER=     itojun@itojun.org

WRKSRC=		${WRKDIR}/tcpd

pre-install:
	${MKDIR} ${PREFIX}/v6/include
	${MKDIR} ${PREFIX}/v6/etc
	${MKDIR} ${PREFIX}/v6/lib
	${MKDIR} ${PREFIX}/v6/libexec

.include <bsd.port.mk>
