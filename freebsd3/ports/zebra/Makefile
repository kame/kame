# New ports collection makefile for:	zebra
# Date created:		So  31 Mai 1998 11:00:30 CEST
# Whom:			Andreas Klemm <andreas@klemm.gtn.com>
#
# $KAME: Makefile,v 1.12 2000/08/18 05:48:32 sumikawa Exp $
#

PORTNAME=	zebra
PORTVERSION=	0.88
CATEGORIES=	net
MASTER_SITES=	ftp://ftp.zebra.org/pub/zebra/
# you might need debugging, it's a developer release !
#CFLAGS+=	-g

MAINTAINER=	sumikawa@kame.net

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
