# New ports collection makefile for:    solid-pop3d
# Version required:     0.14
# Date created:         Tue Feb  1 01:54:45 JST 2000
# Whom:                 sumikawa
#
# $Id: Makefile,v 1.1 2000/01/31 16:57:26 sumikawa Exp $
#

DISTNAME=		solid-pop3d-0.14
PKGNAME=		solidpop3d-0.14
CATEGORIES=		mail
MASTER_SITES=		http://solidpop3d.pld.org.pl/ \
			ftp://ftp.rudykot.pl/pub/solidpop3d/ \
			ftp://sedez.iq.pl/pub/solidpop3d/ \
			ftp://dione.ids.pl/pub/solidpop3d/

PATCH_SITES=		ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=		solidpop3d-014-v6-20000201.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=		itojun@kame.net

GNU_CONFIGURE=		yes
# disable standalone behavior as it listens to single AF_INET6 socket only
CONFIGURE_ARGS+=	--enable-ipv6 --enable-apop --disable-bulletins \
			--disable-standalone

post-install:
	${INSTALL_DATA} ${WRKSRC}/doc/config.example \
		${PREFIX}/etc/spop3d.conf.sample

.include "bsd.port.mk"
