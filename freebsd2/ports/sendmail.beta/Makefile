# New ports collection makefile for:    sendmail
# Version required:	8.10 beta
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.1 1999/11/02 04:27:32 itojun Exp $
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
		${WRKSRC}/../obj.FreeBSD.*/sendmail/sendmail \
		/usr/sbin/sendmail.8.10.0.6

.include <bsd.port.mk>
