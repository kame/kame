# New ports collection makefile for:   icecast
# Date created:		28 Jan 1999
# Whom:			Chip Marshall <chip@eboai.org>
#
# $KAME: Makefile,v 1.3 2001/03/12 12:31:59 itojun Exp $
#

PORTNAME=	icecast
PORTVERSION=	1.1.4
CATEGORIES=	audio net
MASTER_SITES=	http://www.icecast.org/releases/ \
		ftp://ftp.eboai.org/pub/icecast/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	icecast-114-v6-19990527a.diff.gz
PATCH_DIST_STRIP=	-p1

BROKEN=		numerous remote buffer overrun

MAINTAINER=	itojun@kame.net

GNU_CONFIGURE=	yes
CONFIGURE_ARGS=	--with-crypt --with-libwrap

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/icecast ${PREFIX}/sbin
	${INSTALL_PROGRAM} ${WRKSRC}/liveice/liveice ${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/shout/listen ${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/shout/shout ${PREFIX}/bin
	${INSTALL_PROGRAM} ${WRKSRC}/shout/shoutreq ${PREFIX}/bin
	${INSTALL_SCRIPT} ${WRKSRC}/misc/iceplay ${PREFIX}/bin
.if !defined(NOPORTDOCS)
	${MKDIR} ${PREFIX}/share/doc/icecast
	${INSTALL_MAN} ${WRKSRC}/README.v6 ${PREFIX}/share/doc/icecast
	${INSTALL_MAN} ${WRKSRC}/README.multicast ${PREFIX}/share/doc/icecast
	${INSTALL_MAN} ${WRKSRC}/doc/* ${PREFIX}/share/doc/icecast
	${MKDIR} ${PREFIX}/share/examples/icecast
	${INSTALL_MAN} ${WRKSRC}/shout/shoutrc.example ${PREFIX}/share/examples/icecast
	${INSTALL_MAN} ${WRKSRC}/shout/playlist.example ${PREFIX}/share/examples/icecast
	${INSTALL_MAN} ${WRKSRC}/shout/radio.tcl.example ${PREFIX}/share/examples/icecast
	${INSTALL_MAN} ${WRKSRC}/liveice/liveice.cfg ${PREFIX}/share/examples/icecast
	${MKDIR} ${PREFIX}/share/examples/icecast/icedir
	${INSTALL_MAN} ${WRKSRC}/icedir/* ${PREFIX}/share/examples/icecast/icedir
.endif

.include <bsd.port.mk>
