# New ports collection makefile for:	ct
# Date created:		5 Apr 1999 17:00 JST
# Whom:			TANAKA Takashi <tanaka@tahi.org>
#
# $KAME: Makefile,v 1.1 2003/02/07 08:22:04 suz Exp $
# $TAHI: ports/FreeBSD-current/ct/Makefile,v 1.14 2002/11/15 08:21:37 akisada Exp $
#

PORTNAME=	ct
PORTVERSION=	2.0.1
DISTNAME=	${PORTNAME}-${PORTVERSION}
CATEGORIES=	net ipv6
MASTER_SITES=	http://www.tahi.org/release/ct/

MAINTAINER=	tanaka@tahi.org

USE_PERL5=      yes
NO_BUILD=	yes

V6EVALDIR=	${PREFIX}/v6eval

BUILD_DEPENDS=	$(V6EVALDIR)/bin/pktbuf:${.CURDIR}/../v6eval
RUN_DEPENDS=	${BUILD_DEPENDS}:${.CURDIR}/../v6eval

MAKE_ENV+=      "NUTTYPE=host"

.include <bsd.port.mk>
