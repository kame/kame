# Ports collection makefile for:  ppp
# Date created:			  Tue Feb 26
# Whom:				  sumikawa
#
# $KAME: Makefile,v 1.4 2002/06/03 07:14:13 jinmei Exp $
#

PORTNAME=	ppp
PORTVERSION=	020602
CATEGORIES=	net ipv6
MASTER_SITES=	http://www.awfulhak.org/~brian/
DISTNAME=	${PORTNAME}-${PORTVERSION}.src

MAINTAINER=	sumikawa@FreeBSD.org

WRKSRC=		${WRKDIR}/${PORTNAME}-${PORTVERSION}

MAKE_ENV= 	MANDIR=${PREFIX}/man/man \
		INCDIR=${PREFIX}/include

#MANCOMPRESSED=	yes
#MAN3=		libalias.3
#MAN8=		ppp.8 pppctl.8

.include <bsd.port.mk>
