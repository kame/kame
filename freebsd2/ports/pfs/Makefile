# New ports collection makefile for:	pfs
# Version required:	19990608
# Date created:		Mon Jun 14 03:59:27 JST 1999
# Whom:			Jun-ichiro itojun Hagino <itojun@kame.net>
#
# $Id: Makefile,v 1.1 1999/08/09 01:37:16 itojun Exp $
#

DISTNAME=	pfssrc-19990608
CATEGORIES=	net
MASTER_SITES=	http://www.spa.is.uec.ac.jp/%7Etate/pfs/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	itojun@kame.net

GNU_CONFIGURE=	yes

MAN8=	pfscheck.8 pfscs.8 pfsms.8
MAN5=	pfscs.conf.5 pfsms.conf.5

post-patch:
	${CP} ${FILESDIR}/Makefile ${WRKSRC}

do-configure:
	(cd ${WRKSRC}/cs; \
		CC="${CC}" CXX="${CXX}" ac_cv_path_CC="${CC}" \
		CFLAGS="${CFLAGS}" \
		INSTALL="/usr/bin/install -c -o ${BINOWN} -g ${BINGRP}" \
		INSTALL_DATA="${INSTALL_DATA}" \
		INSTALL_PROGRAM="${INSTALL_PROGRAM}" \
		INSTALL_SCRIPT="${INSTALL_SCRIPT}" \
		${CONFIGURE_ENV} ./${CONFIGURE_SCRIPT} ${CONFIGURE_ARGS})
	(cd ${WRKSRC}/ms; \
		CC="${CC}" CXX="${CXX}" ac_cv_path_CC="${CC}" \
		CFLAGS="${CFLAGS}" \
		INSTALL="/usr/bin/install -c -o ${BINOWN} -g ${BINGRP}" \
		INSTALL_DATA="${INSTALL_DATA}" \
		INSTALL_PROGRAM="${INSTALL_PROGRAM}" \
		INSTALL_SCRIPT="${INSTALL_SCRIPT}" \
		${CONFIGURE_ENV} ./${CONFIGURE_SCRIPT} ${CONFIGURE_ARGS})

post-install:
	${MKDIR} ${PREFIX}/share/doc/pfs
	(cd ${WRKSRC}/doc; tar Bpcf - . ) | (cd ${PREFIX}/share/doc/pfs; tar Bpxf -)
	for i in ${MAN8}; do \
		${INSTALL_MAN} ${WRKSRC}/doc/$$i ${PREFIX}/man/man8; \
	done
	for i in ${MAN5}; do \
		${INSTALL_MAN} ${WRKSRC}/doc/$$i ${PREFIX}/man/man5; \
	done

.include <bsd.port.mk>

CONFIGURE_ENV+= CFLAGS=-DINET6 LIBS=-L/usr/local/v6/lib
