# $NetBSD$
#

DISTNAME=	ncftp-3.0.0-src
PKGNAME=	ncftp-3.0.0
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.ncftp.com/ncftp/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	ncftp-300-v6-20000327.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	sumikawa@kame.net

WRKSRC=		${WRKDIR}/${DISTNAME:S/-src//}
GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--with-ncurses
MAN1=		ncftp3.1 ncftpbatch.1 ncftpget.1 ncftpls.1 ncftpput.1
MAN3=		Strn.3
NO_LATEST_LINK=	yes

CONFIGURE_ARGS+=--enable-ipv6
CONFIGURE_ARGS+=--with-ipv6-libraries=/usr/local/v6/lib
CONFIGURE_ARGS+=--with-ipv6-libname=inet6

post-patch:
	@${MV} ${WRKSRC}/ncftp/pref.h ${WRKSRC}/ncftp/pref.h.in
	@${SED} -e 's:/etc/ncftp.firewall:${PREFIX}/etc/ncftp.firewall:' \
		${WRKSRC}/ncftp/pref.h.in > ${WRKSRC}/ncftp/pref.h

do-install:
	@$(INSTALL_PROGRAM) $(WRKSRC)/bin/ncftp $(PREFIX)/bin/ncftp3
	@cd ${WRKSRC}/bin ; $(INSTALL_PROGRAM) \
		ncftpbatch ncftpget ncftpls ncftpput ncftpbookmarks \
		$(PREFIX)/bin
	@$(INSTALL_MAN) $(WRKSRC)/doc/man/ncftp.1 $(PREFIX)/man/man1/ncftp3.1
	@cd ${WRKSRC}/doc/man ; $(INSTALL_MAN) \
		ncftpbatch.1 ncftpget.1 ncftpls.1 ncftpput.1 \
		$(PREFIX)/man/man1
	@$(INSTALL_MAN) $(WRKSRC)/Strn/Strn.3 $(PREFIX)/man/man3

.include <../../mk/bsd.pkg.mk>
