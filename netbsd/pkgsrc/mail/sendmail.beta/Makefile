# New ports collection makefile for:    sendmail6
# Version required:	8.11.0
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.5 2000/07/21 12:45:39 itojun Exp $
#

DISTNAME=	sendmail.${SENDMAILVER}
PKGNAME=	sendmail-8.11.0
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.sendmail.org/pub/sendmail/

MAINTAINER=	itojun@itojun.org

SENDMAILVER=	8.11.0

WRKSRC=		${WRKDIR}/sendmail-${SENDMAILVER}

post-patch:
	${CAT} ${FILESDIR}/site.config.m4 >> ${WRKSRC}/devtools/Site/site.config.m4

do-build:
	@(cd ${WRKSRC}; ./Build)

do-install:
	${MKDIR} ${PREFIX}/libexec/sendmail
	${INSTALL} -c -o root -g kmem -m 6555 \
		${WRKSRC}/../obj.NetBSD.*/sendmail/sendmail \
		${PREFIX}/libexec/sendmail/sendmail.8.11.0

.include "../../mk/bsd.pkg.mk"
