# New ports collection makefile for:    root
# Version required:     1.0
# Date created:         Fri Apr 16 15:52:03 JST 1999
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.1 1999/08/17 09:10:30 itojun Exp $
#

DISTNAME=	rev-v6-address-1.0
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
