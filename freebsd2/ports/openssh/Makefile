# $KAME: Makefile,v 1.7 2001/02/21 06:18:36 itojun Exp $

DISTNAME=	openssh-2.5.1p1
#CATEGORIES=	security net ipv6
CATEGORIES=	security net
# ${MASTER_SITES} is only for if CVS won't work, period.
MASTER_SITES=	ftp://ftp.openssh.com/pub/OpenBSD/OpenSSH/portable/

MAINTAINER=	itojun@kame.net

BUILD_DEPENDS=	${LOCALBASE}/ssl/bin/openssl:${.CURDIR}/../openssl

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
