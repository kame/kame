# New ports collection makefile for:	v6eval
# Date created:		26 Mar 1999 23:00 JST
# Whom:			TANAKA Takashi <tanaka@tahi.org>
#
# $Id: Makefile,v 1.3 1999/11/01 02:39:40 itojun Exp $
#

DISTNAME=	v6eval-0.4
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.tahi.org/pub/TAHI/v6eval/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

PATCH_SITES=	${MASTER_SITES}
PATCHFILES=	v6eval-0.4-openssl094.diff
PATCH_DIST_STRIP=	-p1

MAINTAINER=	tanaka@tahi.org

BUILD_DEPENDS=	openssl:${.CURDIR}/../openssl
RUN_DEPENDS=	$(PERLLIBDIR)/Expect.pm:${WRKSRC}/ports/p5-Expect-1.07 \
		$(PERLLIBDIR)/IO/Stty.pm:${WRKSRC}/ports/p5-IO-Stty-.02 \
		$(PERLLIBDIR)/i386-freebsd/IO/Tty.pm:${WRKSRC}/ports/p5-IO-Tty-0.02 \

USE_PERL5=	yes
V6EVALDIR=	${PREFIX}/v6eval

PERLLIBDIR=	${PREFIX}/lib/perl5/site_perl/${PERL_VER}

post-install:
	@${SED} -e 's#/usr/local#${PREFIX}#' ${PKGDIR}/MESSAGE

.include <bsd.port.mk>
