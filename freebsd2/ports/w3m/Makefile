# New ports collection makefile for:	w3m
# Version required:     990902
# Date created:		Thu Sep 30 10:05:36 JST 1999
# Whom:			sumikawa@kame.net
#
# $Id: Makefile,v 1.1 1999/09/30 23:59:12 itojun Exp $
#

DISTNAME=	w3m-990902
CATEGORIES=	www
MASTER_SITES=	ftp://ei5nazha.yz.yamagata-u.ac.jp/w3m/ \
		ftp://ftp.firedrake.org/w3m/
WRKSRC=		${WRKDIR}/w3m

MAINTAINER=	sumikawa@kame.net

pre-build:
	${SED} -e "s|@PREFIX@|${PREFIX}|g" < ${FILESDIR}/config.h > ${WRKSRC}/config.h

.include <bsd.port.mk>
