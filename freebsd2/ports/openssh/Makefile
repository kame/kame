# New ports collection makefile for:	OpenSSH
# Version required:	1.2
# Date created:		Tue Nov 16 19:45:46 JST 1999
# Whom:			sumikawa
#
# $Id: Makefile,v 1.1 1999/11/16 11:10:42 sumikawa Exp $
#

DISTNAME=	OpenSSH-1.2
CATEGORIES=	security net
MASTER_SITES=	http://www.FreeBSD.org/~green/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	openssh-12-v6-19991116.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	sumikawa@kame.net

# for ports-curret
#LIB_DEPENDS=	crypto.1:${PORTSDIR}/security/openssl
BUILD_DEPENDS=	openssl:${PORTSDIR}/security/openssl

RESTRICTED=	"Links with cryptographic code."

CFLAGS+=	-I${PREFIX}/include
# Here, MANDIR is concetenated to DESTDIR which all forms the man install dir...
MAKE_ENV=	DESTDIR=${PREFIX} MANDIR=/man/man
.if defined(USA_RESIDENT) && ${USA_RESIDENT} == YES
MAKE_ENV+=	CRYPTOLIBS="-L${PREFIX}/lib -lcrypto -lRSAglue -lrsaref"
.else
MAKE_ENV+=	CRYPTOLIBS="-L${PREFIX}/lib -lcrypto"
.endif
WRKSRC=		${WRKDIR}/ssh

post-install:
	@if [ ! -f ${PREFIX}/etc/rc.d/sshd.sh ]; then \
		${ECHO} "Installing ${PREFIX}/etc/rc.d/sshd.sh startup file."; \
		${ECHO} "#!/bin/sh" > ${PREFIX}/etc/rc.d/sshd.sh; \
		${ECHO} "[ -x ${PREFIX}/sbin/sshd ] && ${PREFIX}/sbin/sshd &&" \
			"${ECHO} -n ' sshd'" >> ${PREFIX}/etc/rc.d/sshd.sh; \
		${CHMOD} 755 ${PREFIX}/etc/rc.d/sshd.sh; \
	fi

.include <bsd.port.mk>
