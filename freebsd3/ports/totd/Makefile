# New ports collection makefile for:	totd
# Date created:		6 Oct 1999
# Whom:			feico@pasta.cs.uit.no
#
# $KAME: Makefile,v 1.5 2000/06/25 10:58:48 sumikawa Exp $

PORTNAME=	totd
PORTVERSION=	1.1p4
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.pasta.cs.uit.no/pub/Vermicelli/

MAINTAINER=	feico@pasta.cs.uit.no
HOMEPAGE=	http://www.vermicelli.cs.uit.no/ipv6/software.html

WRKSRC=         ${WRKDIR}/totd-1.1p4

GNU_CONFIGURE=	YES

post-install:
	${INSTALL_SCRIPT} ${FILESDIR}/totd.conf.sample ${PREFIX}/etc/totd.conf.sample

.include <bsd.port.mk>
