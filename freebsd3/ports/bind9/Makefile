# New ports collection makefile for:	bind9
# Date created:		Sat Apr 29 18:50:37 JST 2000
# Whom:			jinmei
#
# $Id: Makefile,v 1.8 2000/08/24 08:24:35 sumikawa Exp $
#

PORTNAME=	bind
PORTVERSION=	9.0.0rc4
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind9/9.0.0rc4/

MAINTAINER=	sumikawa@kame.net

#CONFLICTS=	bind-*
#DEPENDS=	unproven-pthreads-*:../../devel/unproven-pthreads

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--with-mit-pthreads --with-kame

MAN1=		host.1
MAN5=		rndc.conf.5
MAN8=		dnssec-keygen.8 dnssec-makekeyset.8 dnssec-signkey.8 \
		lwresd.8 named.8 nsupdate.8 rndc.8

post-install:
	for i in ${WRKSRC}/doc/man/bin/*.1; do \
		${INSTALL_MAN} $$i ${PREFIX}/man/man1; \
	done
	for i in ${WRKSRC}/doc/man/bin/*.5; do \
		${INSTALL_MAN} $$i ${PREFIX}/man/man5; \
	done
	for i in ${WRKSRC}/doc/man/bin/*.8 ${WRKSRC}/doc/man/dnssec/*.8; do \
		${INSTALL_MAN} $$i ${PREFIX}/man/man8; \
	done

.include "bsd.port.mk"
