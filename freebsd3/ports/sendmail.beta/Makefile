# New ports collection makefile for:    sendmail
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.2 2000/06/25 10:58:44 sumikawa Exp $
#

PORTNAME=	sendmail
PORTVERSION=	8.10.0.10
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.sendmail.org/pub/sendmail/
DISTNAME=	sendmail.${SENDMAILVER}

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
