# New ports collection makefile for:	v6eval
# Date created:		26 Mar 1999 23:00 JST
# Whom:			TANAKA Takashi <tanaka@tahi.org>
#
# $KAME: Makefile,v 1.4 2000/06/25 10:58:48 sumikawa Exp $
#

PORTNAME=	v6eval
PORTVERSION=	0.6
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.tahi.org/pub/TAHI/v6eval/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	tanaka@tahi.org

BROKEN=		"c++ barks"

LIB_DEPENDS=	crypto.1:${PORTSDIR}/security/openssl
RUN_DEPENDS=	$(PERLLIBDIR)/Expect.pm:${WRKSRC}/ports/p5-Expect-1.07 \
		$(PERLLIBDIR)/IO/Stty.pm:${WRKSRC}/ports/p5-IO-Stty-.02 \
		$(PERLLIBDIR)/i386-freebsd/IO/Tty.pm:${WRKSRC}/ports/p5-IO-Tty-0.02 \

USE_PERL5=	yes
V6EVALDIR=	${PREFIX}/v6eval

PERLLIBDIR=	${PREFIX}/lib/perl5/site_perl/${PERL_VER}

SCRIPTLIST=	${WRKDIR}/${DISTNAME}/bin/autorun/autorun \
		${WRKDIR}/${DISTNAME}/bin/pktlint/pktlint

post-patch:
	find ${WRKDIR} -name "*.seq" -or -name "*.rmt" -or -name "*.pl" \
		| xargs ${PERL} ${SCRIPTDIR}/perlpath.pl ${PERL}
	${PERL} ${SCRIPTDIR}/perlpath.pl ${PERL} ${SCRIPTLIST}

post-install:
	@${SED} -e 's#/usr/local#${PREFIX}#' ${PKGDIR}/MESSAGE

.include <bsd.port.mk>
