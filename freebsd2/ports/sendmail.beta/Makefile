# New ports collection makefile for:    sendmail
# Version required:	8.10 beta
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.2 1999/12/28 05:17:35 itojun Exp $
#

DISTNAME=	sendmail.${SENDMAILVER}
PKGNAME=	sendmail-8.10.0.10
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.sendmail.org/pub/sendmail/

MAINTAINER=	itojun@itojun.org

SENDMAILVER=	8.10.0.Beta10

WRKSRC=		${WRKDIR}/sendmail-${SENDMAILVER}/sendmail

post-patch:
	${CAT} ${FILESDIR}/site.config.m4 >> ${WRKSRC}/site.config-v6.kame

do-build:
	@(cd ${WRKSRC}; ./Build -f site.config-v6.kame)

do-install:
	${INSTALL} -c -o root -g kmem -m 6555 \
		${WRKSRC}/../obj.FreeBSD.*/sendmail/sendmail \
		${PREFIX}/sbin/sendmail.8.10.0.10

.include <bsd.port.mk>
