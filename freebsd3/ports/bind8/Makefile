# New ports collection makefile for:	bind (v6 ready)
# Version required:	8.1.2
# Date created:		Fri Dec 25 14:47:35 JST 1998
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.2 1999/08/20 00:43:39 itojun Exp $
#

DISTNAME=	bind-8.1.2
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind/src/8.1.2/
DISTFILES=	bind-8.1.2-src.tar.gz bind-8.1.2-doc.tar.gz

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	bind8-812-v6-19990820a.diff.gz
PATCH_DIST_STRIP=	-p2

# Based on jsager's bind8 port, imported 18 July 1997
MAINTAINER=	itojun@itojun.org

WRKSRC=		${WRKDIR}/src

MAN1=		dig.1 dnsquery.1 host.1
MAN3=		gethostbyname.3 getnetent.3 resolver.3
MAN5=		irs.conf.5 resolver.5
MAN7=		hostname.7 mailaddr.7
MAN8=		named-xfer.8 named.8 ndc.8 nslookup.8

PATCH_ARGS?=	-d ${WRKDIR} -E ${PATCH_STRIP}

post-install:
	${INSTALL_SCRIPT} ${WRKSRC}/bin/named/named-bootconf.pl ${PREFIX}/bin/
	@(cd ${WRKDIR}/doc/man && ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} clean all ${INSTALL_TARGET})

.include <bsd.port.mk>
