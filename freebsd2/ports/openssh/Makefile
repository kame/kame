# $KAME: Makefile,v 1.9 2001/03/26 19:16:08 itojun Exp $

DISTNAME=	openssh-2.5.2p2
#CATEGORIES=	security net ipv6
CATEGORIES=	security net
# ${MASTER_SITES} is only for if CVS won't work, period.
MASTER_SITES=	ftp://ftp.openssh.com/pub/OpenBSD/OpenSSH/portable/

MAINTAINER=	itojun@kame.net

BUILD_DEPENDS=	openssl:${.CURDIR}/../openssl

GNU_CONFIGURE=	yes
CONFIGURE_ARGS=	--without-pam --enable-ipv6
CONFIGURE_ENV=	LIBS="/usr/local/v6/lib/libinet6.a -lcrypt"

BINOWN=	root
BINGRP=	wheel
CONF=	sshd_config ssh_config

post-install:
	for i in ${CONF}; do \
		${INSTALL_DATA} ${WRKSRC}/$$i ${PREFIX}/etc/$$i.dist; \
	done

.include <bsd.port.mk>
