# $NetBSD: Makefile,v 1.12 1998/09/08 22:15:21 tron Exp $
#

DISTNAME=		solid-pop3d-0.14
PKGNAME=		solidpop3d-0.14
CATEGORIES=		mail
MASTER_SITES=		http://solidpop3d.pld.org.pl/ \
			ftp://ftp.rudykot.pl/pub/solidpop3d/ \
			ftp://sedez.iq.pl/pub/solidpop3d/ \
			ftp://dione.ids.pl/pub/solidpop3d/

PATCHFILES=		solidpop3d-014-v6-20000201.diff.gz
PATCH_SITES=		ftp://ftp.kame.net/pub/kame/misc/
PATCH_DIST_STRIP=	-p1

MAINTAINER=		itojun@kame.net
HOMEPAGE=		http://solidpop3d.pld.org.pl/download.html

GNU_CONFIGURE=		yes
CONFIGURE_ARGS+=	--enable-ipv6 --enable-apop --disable-bulletins

# popper makefile doesn't have an install target...
post-install:
	${INSTALL_DATA} ${WRKSRC}/doc/config.example \
		${PREFIX}/etc/spop3d.conf.sample

.include "../../mk/bsd.pkg.mk"
