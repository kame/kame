# New ports collection makefile for:    sendmail6
# Version required:	8.10Beta
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.2 1999/12/28 05:02:16 itojun Exp $
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
	${MKDIR} ${PREFIX}/libexec/sendmail
	${INSTALL} -c -o root -g kmem -m 6555 \
		${WRKSRC}/../obj.NetBSD.*/sendmail/sendmail \
		${PREFIX}/libexec/sendmail/sendmail.8.10.0.10

.include "../../mk/bsd.pkg.mk"
