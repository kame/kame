# New ports collection makefile for:	tcptrace
# Version required:	5.1.1
# Date created:		3 March 1997
# Whom:			fenner
#
# $Id: Makefile,v 1.1.1.2 1999/08/10 09:14:44 itojun Exp $
#

DISTNAME=	tcptrace.5.1.1
PKGNAME=	tcptrace-5.1.1
CATEGORIES=	net
MASTER_SITES=	http://jarok.cs.ohiou.edu/software/tcptrace/files/5.1.1/

PATCHFILES=	tcptrace-5.1.1-IPv6-19990119.diff.gz
PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/

MAINTAINER=	fenner@FreeBSD.ORG

GNU_CONFIGURE=	yes
WRKSRC=		${WRKDIR}/tcptrace_5.1.1
ALL_TARGET=	tcptrace

DOCFILES=	ARGS BUGS CHANGES COPYRIGHT FAQ README README.mailing_list \
		README.modules README.tput_graphs WWW

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/tcptrace ${PREFIX}/bin
.if !defined(NOPORTDOCS)
	${MKDIR} ${PREFIX}/share/doc/tcptrace
.for file in ${DOCFILES}
	${INSTALL_DATA} ${WRKSRC}/${file} ${PREFIX}/share/doc/tcptrace
.endfor
.endif

.include "../../mk/bsd.pkg.mk"
