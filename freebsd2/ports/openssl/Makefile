# New ports collection makefile for:	OpenSSL
# Version required:	0.9.6
# Date created:		Sun Jan  3 19:36:27 CET 1999
# Whom:			Dirk Froemberg <dirk@FreeBSD.org>
#
# $FreeBSD: ports/security/openssl/Makefile,v 1.35 1999/08/31 01:51:23 peter Exp $
#

DISTNAME=	openssl-0.9.6
CATEGORIES=	security devel 
MASTER_SITES=	http://www.openssl.org/source/ \
		ftp://ftp.openssl.org/source/ \
		ftp://ftp.sunet.se/pub/security/tools/net/openssl/source/ \
		ftp://ftp.cert.dfn.de/pub/tools/net/openssl/source/

MAINTAINER=	itojun@kame.net

RESTRICTED=	"Cryptography"
USE_PERL5=	yes

do-configure:
	@cd ${WRKSRC} \
	&& ${SETENV} CC="${CC}" CFLAGS="${CFLAGS}" PERL="${PERL}" \
	   ./config --prefix=${PREFIX} --openssldir=${PREFIX}/openssl \
	   -L${PREFIX}/lib

post-install:
	@${SED} -e 's#/usr/local#${PREFIX}#g' ${PKGDIR}/MESSAGE

.include <bsd.port.mk>
