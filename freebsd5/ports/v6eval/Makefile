# New ports collection makefile for:	v6eval
# Date created:		26 Mar 1999 23:00 JST
# Whom:			TANAKA Takashi <tanaka@tahi.org>
#
# $KAME: Makefile,v 1.1 2003/02/07 08:22:04 suz Exp $
# $TAHI: ports/FreeBSD-current/v6eval/Makefile,v 1.15 2002/11/15 08:21:38 akisada Exp $
#

PORTNAME=	v6eval
PORTVERSION=	2.0.1
CATEGORIES=	net ipv6
MASTER_SITES=	http://www.tahi.org/release/v6eval/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	tanaka@tahi.org

RUN_DEPENDS=	$(PERLLIBDIR)/Expect.pm:${PORTSDIR}/lang/p5-Expect

USE_PERL5=	yes
USE_OPENSSL=	yes
PERLLIBDIR=	${PREFIX}/lib/perl5/site_perl/${PERL_VER}

post-install:
	@${SED} -e 's#/usr/local#${PREFIX}#' ${PKGMESSAGE}

.include <bsd.port.mk>
