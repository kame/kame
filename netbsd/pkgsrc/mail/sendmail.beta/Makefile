# New ports collection makefile for:    sendmail6
# Version required:	8.9.x+IPv6 patch x
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.1 1999/11/02 10:19:02 itojun Exp $
#

DISTNAME=	sendmail.${SENDMAILVER}
PKGNAME=	sendmail-8.10.0.6
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.sendmail.org/pub/sendmail/

MAINTAINER=	itojun@itojun.org

SENDMAILVER=	8.10.0.Beta6

WRKSRC=		${WRKDIR}/sendmail-${SENDMAILVER}/sendmail

post-patch:
	${CAT} ${FILESDIR}/site.config.m4 >> ${WRKSRC}/site.config-v6.kame

do-build:
	@(cd ${WRKSRC}; ./Build -f site.config-v6.kame)

do-install:
	${INSTALL} -c -o root -g kmem -m 6555 \
		${WRKSRC}/../obj.NetBSD.*/sendmail/sendmail \
		${PREFIX}/sbin/sendmail.8.10.0.6

.include "../../mk/bsd.pkg.mk"
