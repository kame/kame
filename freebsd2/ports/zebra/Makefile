# New ports collection makefile for:	zebra
# Version required:	0.86
# Date created:		So  31 Mai 1998 11:00:30 CEST
# Whom:			Andreas Klemm <andreas@klemm.gtn.com>
#
# $Id: Makefile,v 1.10 2000/04/28 10:30:11 itojun Exp $
#

DISTNAME=	zebra-0.86
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.zebra.org/pub/zebra/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	andreas@FreeBSD.org

GNU_CONFIGURE=	yes
CONFIGURE_ARGS+=--sysconfdir=${PREFIX}/etc/zebra

post-install:
	@${ECHO} "===>     installing zebra startup file..."
	@${SED} -e "s=!!PREFIX!!=${PREFIX}=" \
		< ${FILESDIR}/zebra.sh  \
		> ${PREFIX}/etc/rc.d/zebra.sh.sample
	@chmod 555 ${PREFIX}/etc/rc.d/zebra.sh.sample
	@${ECHO} "===>     done."

.include <bsd.port.mk>
