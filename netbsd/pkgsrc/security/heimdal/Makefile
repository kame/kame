# New ports collection makefile for:	heimdal
# Version required:	0.2p
# Date created:		Fri Jun 19 15:07:04 JST 1998
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.6 2000/02/21 06:26:25 itojun Exp $
#

DISTNAME=	heimdal-0.2p
CATEGORIES=	security
MASTER_SITES=	ftp://ftp.pdc.kth.se/pub/heimdal/src/

HOMEPAGE=	http://www.pdc.kth.se/heimdal/
MAINTAINER=	itojun@itojun.org

GNU_CONFIGURE=	yes

# for bin/des
CONFLICTS=	openssl-0.9.2b

post-install:
	${MKDIR} ${PREFIX}/share/heimdal/examples
	${INSTALL_DATA} ${WRKSRC}/krb5.conf \
		${PREFIX}/share/heimdal/examples/krb5.conf.sample
	${INSTALL_DATA} ${FILESDIR}/inetd.conf \
		${PREFIX}/share/heimdal/examples/inetd.conf.sample
	${INSTALL_DATA} ${FILESDIR}/services \
		${PREFIX}/share/heimdal/examples/services.sample
	# working dir
	${MKDIR} /var/heimdal

.include "../../mk/bsd.pkg.mk"

CONFIGURE_ENV+=	INSTALL_PROGRAM=
