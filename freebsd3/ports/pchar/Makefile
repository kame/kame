# Ports collection makefile for:  pchar
# Date created:			  Wed Nov 03, 1999
# Whom:				  David O'Brien (obrien@NUXI.com)
#
# $FreeBSD: ports/net/pchar/Makefile,v 1.5 2000/01/24 23:20:51 obrien Exp $
#

PORTNAME=	pchar
PORTVERSION=	1.2
CATEGORIES=	net #ipv6
MASTER_SITES=	http://www.employees.org/~bmah/Software/pchar/

MAINTAINER=	sumikawa@kame.net

GNU_CONFIGURE=	yes
MAN8=		pchar.8

.include <bsd.port.pre.mk>

#.if ${OSVERSION} >= 400014
CONFIGURE_ARGS= --with-ipv6=/usr/local/v6
#.endif

.if !defined(NOPORTDOCS)
post-install:
	@${MKDIR} ${PREFIX}/share/doc/pchar
	cd ${WRKSRC} ; ${INSTALL_DATA} README FAQ ${PREFIX}/share/doc/pchar
.endif

.include <bsd.port.post.mk>
