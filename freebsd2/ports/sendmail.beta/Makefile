# New ports collection makefile for:    sendmail
# Version required:	8.10.1
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.5 2000/08/31 11:03:38 itojun Exp $
#

DISTNAME=	sendmail.${SENDMAILVER}
PKGNAME=	sendmail-${SENDMAILVER}
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
	${INSTALL} -c -o root -m 4555 \
		${WRKSRC}/obj.FreeBSD.*/sendmail/sendmail \
		${PREFIX}/sbin/sendmail.${SENDMAILVER}

.include <bsd.port.mk>
