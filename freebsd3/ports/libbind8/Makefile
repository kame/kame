# New ports collection makefile for:	bind (v6 ready)
# Date created:		Fri Dec 25 14:47:35 JST 1998
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.6 2001/01/02 10:42:23 jinmei Exp $
#

PORTNAME=	libbind
PORTVERSION=	8.2.2p7
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind/src/8.2.2-P7/
DISTFILES=	bind-src.tar.gz bind-doc.tar.gz

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	libbind-822p7-v6-20010107a.diff.gz
PATCH_DIST_STRIP=	-p2

MAINTAINER=	jinmei@kame.net

WRKSRC=		${WRKDIR}/src

#MAN1=		dig.1 dnsquery.1 host.1
MAN3=		gethostbyname.3 getnetent.3 resolver.3
#MAN5=		irs.conf.5 resolver.5
#MAN7=		hostname.7 mailaddr.7
#MAN8=		named-xfer.8 named.8 ndc.8 nslookup.8

PATCH_ARGS?=	-d ${WRKDIR} -E ${PATCH_STRIP}

post-install:
	@(cd ${WRKDIR}/doc/man && ${SETENV} ${MAKE_ENV} ${MAKE} ${MAKE_FLAGS} ${MAKEFILE} clean all ${INSTALL_TARGET})

.include <bsd.port.mk>
