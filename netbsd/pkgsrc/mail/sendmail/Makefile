# New ports collection makefile for:    sendmail6
# Version required:	8.9.x+IPv6 patch x
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.1 1999/08/08 23:59:22 itojun Exp $
#

DISTNAME=	sendmail.${SENDMAILVER}
PKGNAME=	sendmail6-${SENDMAILVER}${PATCHVER}
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.kyoto.wide.ad.jp/pub/mail/smtpfeed/ \
		ftp://ftp.kyoto.wide.ad.jp/pub/mail/sendmail/ \
		ftp://ftp.sendmail.org/pub/sendmail/

PATCH_SITES=	${MASTER_SITES}
PATCHFILES=	sendmail.${SENDMAILVER}${PATCHVER}.patch \
		sendmail${WIDEPATCHVER}.patch.gz

MAINTAINER=	itojun@itojun.org

SENDMAILVER=	8.9.1
PATCHVER=	a
WIDEPATCHVER=	891+3.1W

WRKSRC=		${WRKDIR}/sendmail-${SENDMAILVER}/src

post-patch:
	${CAT} ${FILESDIR}/site.config.m4 >> ${WRKSRC}/site.config-v6.kame

do-build:
	@(cd ${WRKSRC}; ./Build -f site.config-v6.kame)

do-install:
	${INSTALL} -c -o root -g kmem -m 6555 ${WRKSRC}/obj.FreeBSD.*/sendmail \
		/usr/sbin/sendmail6
	${MKDIR} ${PREFIX}/share/doc/sendmail${SENDMAILVER}
	for i in FAQ LICENSE README; do \
		${INSTALL_DATA} ${WRKSRC}/../$$i \
			${PREFIX}/share/doc/sendmail${SENDMAILVER}; \
	done
	for i in 00READ_ME.WIDE 00READ_ME.WIDE.j 00READ_ME.v6; do \
		${INSTALL_DATA} ${WRKSRC}/$$i \
			${PREFIX}/share/doc/sendmail${SENDMAILVER}; \
	done

.include <bsd.port.mk>
