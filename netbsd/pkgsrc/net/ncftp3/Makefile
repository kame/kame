# New ports collection makefile for:    ncftp3
# Version required:     3.0
# Date created:         4 Nov 1994
# Whom:                 ache
#
# $Id: Makefile,v 1.2 1999/08/25 10:58:07 sumikawa Exp $
#

DISTNAME=	ncftp-3.0beta19-src
PKGNAME=	ncftp-3.0b19
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.ncftp.com/ncftp/3.0BETA/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/ \
		ftp://ftp.v6.kame.net/pub/kame/misc/
PATCHFILES=	ncftp-30b19-19990825.diff.gz
PATCH_DIST_STRIP=	-p

MAINTAINER=	sumikawa@kame.net

WRKSRC=		${WRKDIR}/${DISTNAME:S/-src//}
GNU_CONFIGURE=	yes
CONFIGURE_ARGS=	--with-ncurses
MAN1=		ncftp3.1 ncftpbatch.1 ncftpget.1 ncftpls.1 ncftpput.1
MAN3=		Strn.3
NO_LATEST_LINK=	yes

#.if ${PORTOBJFORMAT} == "elf"
#LIBNCFTP= libncftp.so.2
#LIBSTRN=libStrn.so.1
#.else
#LIBNCFTP= libncftp.so.2.0
#LIBSTRN=libStrn.so.1.0
#.endif

post-patch:
	@${MV} ${WRKSRC}/ncftp/pref.h ${WRKSRC}/ncftp/pref.h.in
	@${SED} -e 's:/etc/ncftp.firewall:${PREFIX}/etc/ncftp.firewall:' \
		${WRKSRC}/ncftp/pref.h.in > ${WRKSRC}/ncftp/pref.h

#pre-build:
#	cd ${WRKSRC}/Strn ; make so
#	cd ${WRKSRC}/libncftp ; make so

do-install:
	@$(INSTALL_PROGRAM) $(WRKSRC)/bin/ncftp $(PREFIX)/bin/ncftp3
	@cd ${WRKSRC}/bin ; $(INSTALL_PROGRAM) \
		ncftpbatch ncftpget ncftpls ncftpput ncftpbookmarks \
		$(PREFIX)/bin
#	@$(INSTALL_DATA) $(WRKSRC)/Strn/libStrn.so.1 $(PREFIX)/lib/$(LIBSTRN)
#	@cd $(PREFIX)/lib && ${LN} -sf $(LIBSTRN) libStrn.so
#	@$(INSTALL_DATA) $(WRKSRC)/libncftp/libncftp.so.2 $(PREFIX)/lib/$(LIBNCFTP)
#	@cd $(PREFIX)/lib && ${LN} -sf $(LIBNCFTP) libncftp.so
#	@${SETENV} OBJFORMAT=${PORTOBJFORMAT} ${LDCONFIG} -m ${PREFIX}/lib
	@$(INSTALL_MAN) $(WRKSRC)/doc/man/ncftp.1 $(PREFIX)/man/man1/ncftp3.1
	@cd ${WRKSRC}/doc/man ; $(INSTALL_MAN) \
		ncftpbatch.1 ncftpget.1 ncftpls.1 ncftpput.1 \
		$(PREFIX)/man/man1
	@$(INSTALL_MAN) $(WRKSRC)/Strn/Strn.3 $(PREFIX)/man/man3

.include <../../mk/bsd.pkg.mk>
