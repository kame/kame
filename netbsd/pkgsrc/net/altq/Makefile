# New ports collection makefile for:	altq userland
# Version required:			2.0
# Date created:				Wed Jul  1 12:50:42 JST 1998
# Whom:					itojun
#
# $Id: Makefile,v 1.2 1999/10/02 17:20:30 itojun Exp $
#

DISTNAME=	altq-2.0
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.csl.sony.co.jp/pub/kjc/

MAINTAINER=	itojun@kame.net

MAKE_ENV+=	SYS_DEFINES=-DINET6 SYS_LIBS="-L/usr/local/v6/lib -linet6" \
		SYS_INCLUDES="" SUBDIRS="atm-tools" COPY="-c"

MAN4=	en.4 pvc.4 natm.4
MAN5=	altq.conf.5
MAN8=	pvcbridge.8 pvcsif.8 pvctxctl.8 \
	altqd.8 cbqd.8 fifoqd.8 redd.8 riod.8 wfqd.8

post-install:
	# manpages
	for i in en.4 natm.4 pvc.4; do\
		${INSTALL_MAN} ${WRKSRC}/atm-tools/$$i ${PREFIX}/man/man4;\
	done
	for i in altq.conf.5; do\
		${INSTALL_MAN} ${WRKSRC}/docs/$$i ${PREFIX}/man/man5;\
	done
	for i in pvcbridge.8 pvcsif.8 pvctxctl.8; do\
		${INSTALL_MAN} ${WRKSRC}/atm-tools/$$i ${PREFIX}/man/man8;\
	done
	for i in altqd.8 cbqd.8 fifoqd.8 redd.8 riod.8 wfqd.8; do\
		${INSTALL_MAN} ${WRKSRC}/docs/$$i ${PREFIX}/man/man8;\
	done
	# docs
	${MKDIR} ${PREFIX}/share/doc/altq
	for i in PERF.txt TIPS.txt cbq-howto.txt how-to-modify-drivers.txt \
		qop_api.txt rsvp-and-cbq-by-sally.txt wfq.txt; do\
		${INSTALL_DATA} ${WRKSRC}/docs/$$i ${PREFIX}/share/doc/altq;\
	done
	for i in CHANGES INSTALL MAKEDEV.altq README; do\
		${INSTALL_DATA} ${WRKSRC}/$$i ${PREFIX}/share/doc/altq;\
	done
#	@${CAT} ${PKGDIR}/MESSAGE

makedev:
	(cd ${WRKSRC}; sh MAKEDEV.altq all)

.include "../../mk/bsd.pkg.mk"
