# New ports collection makefile for:	tcptrace
# Version required:	5.2.1
# Date created:		3 March 1997
# Whom:			fenner
#
# $Id: Makefile,v 1.2 1999/09/16 00:42:50 itojun Exp $
#

DISTNAME=	tcptrace.5.2.1
PKGNAME=	tcptrace-5.2.1
CATEGORIES=	net
MASTER_SITES=	http://jarok.cs.ohiou.edu/software/tcptrace/files/5.2.1/

MAINTAINER=	itojun@kame.net

GNU_CONFIGURE=	yes
WRKSRC=		${WRKDIR}/tcptrace_5.2.1
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

.include <bsd.port.mk>
