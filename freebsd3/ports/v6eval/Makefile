# New ports collection makefile for:	v6eval
# Version required:			0.1
# Date created:		26 Mar 1999 23:00 JST
# Whom:			TANAKA Takashi <tanaka@tahi.org>
#
# $Id: Makefile,v 1.1 1999/08/17 09:10:49 itojun Exp $
#

DISTNAME=	v6eval-0.1
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.tahi.org/pub/TAHI/v6eval/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	tanaka@tahi.org

RUN_DEPENDS=	$(PERLLIBDIR)/Expect.pm:${WRKSRC}/ports/p5-Expect-1.07 \
		$(PERLLIBDIR)/IO/Stty.pm:${WRKSRC}/ports/p5-IO-Stty-.02 \
		$(PERLLIBDIR)/i386-freebsd/IO/Tty.pm:${WRKSRC}/ports/p5-IO-Tty-0.02 \

USE_PERL5=      yes
V6EVALDIR=	${PREFIX}/v6eval

PERLLIBDIR=	${PREFIX}/lib/perl5/site_perl/${PERL_VER}

post-install:
	@${SED} -e 's#/usr/local#${PREFIX}#' ${PKGDIR}/MESSAGE

.include <bsd.port.mk>
