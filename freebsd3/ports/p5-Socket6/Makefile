# New ports collection makefile for:	Socket6
# Version required:	0.06
# Date created:		13 March 2000
# Whom:	      		Hajimu UMEMOTO <ume@FreeBSD.org>
#
# $FreeBSD$
#

DISTNAME=	Socket6-0.07
PKGNAME=	p5-Socket6-0.07
CATEGORIES=	net perl5 #ipv6
MASTER_SITES=	${MASTER_SITE_PERL_CPAN}
MASTER_SITE_SUBDIR=	Socket6

MAINTAINER=	ume@FreeBSD.org

USE_PERL5=	yes

do-configure:
	@cd ${WRKSRC}; ${SETENV} ${MAKE_ENV} ${PERL5} Makefile.PL \
		CCFLAGS="${CFLAGS}"

.include <bsd.port.mk>
