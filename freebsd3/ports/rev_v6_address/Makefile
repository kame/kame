# New ports collection makefile for:    rev-v6-address
# Date created:         Fri Apr 16 15:52:03 JST 1999
# Whom:                 sumikawa
#
# $KAME: Makefile,v 1.2 2000/06/25 10:58:44 sumikawa Exp $
#

PORTNAME=	rev-v6-address
PORTVERSION=	1.0
CATEGORIES=	textproc
MASTER_SITES=	http://www.fumi.org/lib/
DISTFILES=	rev_v6_address.c

MAINTAINER=	sumikawa@kame.net

do-extract:
	@${RM} -rf ${WRKDIR}
	@${MKDIR} ${WRKDIR}
	@${CP} ${_DISTDIR}/${DISTFILES} ${WRKDIR}

do-build:
	(cd ${WRKDIR}; ${CC} ${CFLAGS} -o rev_v6_address ${DISTFILES})

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/rev_v6_address ${PREFIX}/bin

NO_INSTALL_MANPAGES=	yes

.include <bsd.port.mk>
