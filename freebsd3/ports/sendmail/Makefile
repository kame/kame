# New ports collection makefile for:    sendmail
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.1 2000/10/15 11:06:33 sumikawa Exp $
#

PORTNAME=	sendmail
PORTVERSION=	8.11.1
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.sendmail.org/pub/sendmail/
DISTNAME=	${PORTNAME}.${PORTVERSION}

MAINTAINER=	itojun@itojun.org

WRKSRC=		${WRKDIR}/${PORTNAME}-${PORTVERSION}/${PORTNAME}

post-patch:
	${CAT} ${FILESDIR}/site.config.m4 >> ${WRKSRC}/site.config-v6.kame

do-build:
	@(cd ${WRKSRC}; ./Build -f site.config-v6.kame)

do-install:
	${INSTALL} -c -o root -g kmem -m 6555 \
		${WRKSRC}/../obj.FreeBSD.*/sendmail/sendmail \
		${PREFIX}/sbin/sendmail.${PORTVERSION}

.include <bsd.port.mk>
