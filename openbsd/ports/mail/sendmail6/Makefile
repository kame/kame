# New ports collection makefile for:    sendmail6
# Version required:	8.9.x+IPv6 patch x
# Date created:		1 Oct 1997
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.1.1.2 1999/08/10 09:14:34 itojun Exp $
#

DISTNAME=	sendmail.${SENDMAILVER}
PKGNAME=	sendmail6-${SENDMAILVER}${PATCHVER}
CATEGORIES=	mail
MASTER_SITES=	ftp://ftp.kyoto.wide.ad.jp/pub/mail/smtpfeed/ \
		ftp://ftp.kyoto.wide.ad.jp/pub/mail/sendmail/ \
		ftp://ftp.sendmail.org/pub/sendmail/
DISTFILES=	${DISTNAME}${EXTRACT_SUFX}
EXTRACT_ONLY=	${DISTNAME}${EXTRACT_SUFX}

PATCH_SITES=	${MASTER_SITES}
#PATCHFILES+=	sendmail.${SENDMAILVER}${PATCHVER}.patch
PATCHFILES+=	sendmail${WIDEPATCHVER}.patch.gz

# ipsec hack
#MASETER_SITES+=	ftp://ftp.kame.net/pub/kame/misc/
#IPSECHACK=	sendmail.893+W3.2.kame-ipsec.19990521.diff.gz
#DISTFILES+=	${IPSECHACK}

MAINTAINER=	itojun@itojun.org

SENDMAILVER=	8.9.3
#PATCHVER=	a
WIDEPATCHVER=	893+3.2W

WRKSRC=		${WRKDIR}/sendmail-${SENDMAILVER}/src

post-patch:
	${CAT} ${FILESDIR}/site.config.m4 >> ${WRKSRC}/site.config-v6.kame
	@(cd ${WRKSRC}/..; ${GUNZIP_CMD} -c ${DISTDIR}/${IPSECHACK} | ${PATCH} -p1 -f --quiet)

do-build:
	@(cd ${WRKSRC}; ./Build -f site.config-v6.kame)

do-install:
	${INSTALL} -c -o root -g kmem -m 6555 ${WRKSRC}/obj.OpenBSD.*/sendmail \
		${PREFIX}/sbin/sendmail6
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
