# New ports collection makefile for:	ct
# Date created:		5 Apr 1999 17:00 JST
# Whom:			TANAKA Takashi <tanaka@tahi.org>
#
# $KAME: Makefile,v 1.3 2000/06/25 10:58:31 sumikawa Exp $
#

PORTNAME=	ct
PORTVERSION=	0.6
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.tahi.org/pub/TAHI/ct/

MAINTAINER=	tanaka@tahi.org

USE_PERL5=      yes
NO_BUILD=	yes

V6EVALDIR=	${PREFIX}/v6eval

BUILD_DEPENDS=	$(V6EVALDIR)/bin/pktbuf:${.CURDIR}/../v6eval
RUN_DEPENDS=	$(V6EVALDIR)/bin/pktbuf:${.CURDIR}/../v6eval

post-patch:
	find ${WRKDIR} -name "*.seq" -or -name "*.rmt" -or -name "*.pm" \
		| xargs ${PERL} ${SCRIPTDIR}/perlpath.pl ${PERL}

.include <bsd.port.mk>
