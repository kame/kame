#

DISTNAME=       lukemftp-1.5
CATEGORIES=	net
MASTER_SITES=   ftp://ftp.netbsd.org/pub/NetBSD/misc/lukemftp/

MAINTAINER=     itojun@kame.net

GNU_CONFIGURE=	yes
CONFIGURE_ENV+=	LIBS="-L/usr/local/v6/lib -linet6"

MAN1=	ftp.1

post-install:
	${INSTALL_MAN} ${WRKSRC}/src/ftp.1 ${PREFIX}/man/man1

.include <bsd.port.mk>
