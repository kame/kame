# New ports collection makefile for:	gated-ipv6
# Version required:	199903
# Date created:		Wed Oct 21 11:39:18 JST 1998
# Whom:			itojun
#
# $Id: Makefile,v 1.1.1.1.2.1 1999/10/12 05:15:27 itojun Exp $
#

DISTNAME=	gated-pubipv6-snapshot.031999
PKGNAME=	gated-ipv6-19990300
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.gated.org/net-research/gated/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	gatedv6-snap0399-19990330.diff.gz
PATCH_DIST_STRIP=	-p2

MAINTAINER=	itojun@itojun.org
HOMEPAGE=	http://www.gated.org/

BROKEN=		"patch uses nonstandard struct field"

NO_PACKAGE=	"binary redistribution restricted to members"
NO_CDROM=	"binary redistribution restricted to members"

WRKSRC=		${WRKDIR}/gated-pub-ipv6-snapshot-0399/src
CONFIGFILE=	${FILESDIR}/Config
OBJDIR=		${WRKSRC}/obj.`${WRKSRC}/util/archtype`

MAN8=	gated.8 gdc.8 ripquery.8
DOCS=	Acknowledgements BUGS CHANGES CHANGES.1 Consortium_Agreement \
	Copyright Copyright.ISIS Copyright.OSPF INSTALL \
	ISIS-config.ps Licensing README README.bgp README.make \
	README.v6 RELEASE TODO

post-patch:
	${MKDIR} ${OBJDIR}
	${SED} -e 's#@PREFIX@#${PREFIX}#g' ${CONFIGFILE} > ${OBJDIR}/Config

do-configure:
	(cd ${WRKSRC}; make config)

post-install:
	for i in ${MAN8}; do \
		${CP} ${OBJDIR}/$$i ${PREFIX}/man/man8; \
	done
.if !defined(NOPORTDOCS)
	${MKDIR} ${PREFIX}/share/doc/gated-ipv6
	${CP} -r ${WRKSRC}/../doc/* ${PREFIX}/share/doc/gated-ipv6
	${MKDIR} ${PREFIX}/share/examples/gated-ipv6
	${CP} -r ${WRKSRC}/../conf/* ${PREFIX}/share/examples/gated-ipv6
	for i in ${DOCS}; do \
		${CP} ${WRKSRC}/../$$i ${PREFIX}/share/doc/gated-ipv6; \
	done
.endif

.include "../../mk/bsd.pkg.mk"
