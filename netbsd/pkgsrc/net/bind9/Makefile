# $NetBSD$

DISTNAME=	bind-9.0.0
PKGNAME=	bind-9.0.0
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.isc.org/isc/bind9/9.0.0/

MAINTAINER=	itojun@kame.net
HOMEPAGE=	http://www.isc.org/

BROKEN=		"old veresion, use NetBSD pkgsrc"

#CONFLICTS=	bind-*
DEPENDS=	unproven-pthreads-*:../../devel/unproven-pthreads

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=	--with-mit-pthreads --with-kame

post-install:
	for i in ${WRKSRC}/doc/man/bin/*.1; do \
		${INSTALL_MAN} $$i ${PREFIX}/man/man1; \
	done
	for i in ${WRKSRC}/doc/man/bin/*.5; do \
		${INSTALL_MAN} $$i ${PREFIX}/man/man5; \
	done
	for i in ${WRKSRC}/doc/man/bin/*.8 ${WRKSRC}/doc/man/dnssec/*.8; do \
		${INSTALL_MAN} $$i ${PREFIX}/man/man8; \
	done

.include "../../mk/bsd.pkg.mk"
