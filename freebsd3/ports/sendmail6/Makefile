# New ports collection makefile for:    sendmail6
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $KAME: Makefile,v 1.2 2000/06/25 10:58:45 sumikawa Exp $
#

PORTNAME=	sendmail
PORTVERSION=	8.9.3
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.kyoto.wide.ad.jp/pub/mail/smtpfeed/ \
		ftp://ftp.kyoto.wide.ad.jp/pub/mail/sendmail/ \
		ftp://ftp.sendmail.org/pub/sendmail/
DISTNAME=	${PORTNAME}.${PORTVERSION}

PATCH_SITES=	${MASTER_SITES}
PATCHFILES+=	sendmail${WIDEPATCHVER}.patch.gz

MAINTAINER=	itojun@itojun.org

WIDEPATCHVER=	893+3.2W

WRKSRC=		${WRKDIR}/${PKGNAME}/src

post-patch:
	${CAT} ${FILESDIR}/site.config.m4 >> ${WRKSRC}/site.config-v6.kame

do-build:
	@(cd ${WRKSRC}; ./Build -f site.config-v6.kame)

do-install:
	${INSTALL} -c -o root -g kmem -m 6555 ${WRKSRC}/obj.FreeBSD.*/sendmail \
		/usr/sbin/sendmail6
	${MKDIR} ${PREFIX}/share/doc/sendmail${PORTVERSION}
	for i in FAQ LICENSE README; do \
		${INSTALL_DATA} ${WRKSRC}/../$$i \
			${PREFIX}/share/doc/sendmail${PORTVERSION}; \
	done
	for i in 00READ_ME.WIDE 00READ_ME.WIDE.j 00READ_ME.v6; do \
		${INSTALL_DATA} ${WRKSRC}/$$i \
			${PREFIX}/share/doc/sendmail${PORTVERSION}; \
	done

.include <bsd.port.mk>
