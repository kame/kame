# New ports collection makefile for:	tcptrace
# Date created:		3 March 1997
# Whom:			fenner
#
# $KAME: Makefile,v 1.3 2000/06/25 10:58:47 sumikawa Exp $
#

PORTNAME=	tcptrace
PORTVERSION=	5.2.1
CATEGORIES=	net
MASTER_SITES=	http://jarok.cs.ohiou.edu/software/tcptrace/files/5.2.1/
DISTNAME=	${PORTNAME}.${PORTVERSION}

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
