# New ports collection makefile for:	ct
# Date created:		5 Apr 1999 17:00 JST
# Whom:			TANAKA Takashi <tanaka@tahi.org>
#
# $KAME: Makefile,v 1.2 2000/12/01 11:17:55 sumikawa Exp $
#

PORTNAME=	ct
PORTVERSION=	1.2
CATEGORIES=	net ipv6
MASTER_SITES=	ftp://ftp.tahi.org/pub/TAHI/ct/

MAINTAINER=	tanaka@tahi.org

USE_PERL5=      yes
NO_BUILD=	yes

V6EVALDIR=	${PREFIX}/v6eval

BUILD_DEPENDS=	$(V6EVALDIR)/bin/pktbuf:${.CURDIR}/../v6eval
RUN_DEPENDS=	${BUILD_DEPENDS}:${.CURDIR}/../v6eval

MAKE_ENV+=      "NUTTYPE=host"

.include <bsd.port.mk>
