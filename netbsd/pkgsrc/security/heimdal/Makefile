# New ports collection makefile for:	heimdal
# Version required:	0.1c
# Date created:		Fri Jun 19 15:07:04 JST 1998
# Whom:			itojun@itojun.org
#
# $Id: Makefile,v 1.1 1999/08/10 09:14:49 itojun Exp $
#

DISTNAME=	heimdal-0.1c
CATEGORIES=	security
MASTER_SITES=	ftp://ftp.pdc.kth.se/pub/heimdal/src/

MAINTAINER=	itojun@itojun.org

GNU_CONFIGURE=	yes

MAN3=	krb5_warn.3 krb5_openlog.3 krb5_425_conv_principal.3 \
	krb5_build_principal.3 krb5_free_principal.3 \
	krb5_parse_name.3 krb5_sname_to_principal.3 \
	krb5_unparse_name.3
MAN5=	krb5.conf.5
MAN1=	kinit.1 klist.1 kdestroy.1 kpasswd.1
MAN8=	kdc.8 kstash.8 hprop.8 hpropd.8 ktutil.8 kpasswdd.8

post-install:
	${MKDIR} ${PREFIX}/share/heimdal/examples
	${INSTALL_DATA} ${WRKSRC}/krb5.conf \
		${PREFIX}/share/heimdal/examples/krb5.conf.sample
	${INSTALL_DATA} ${FILESDIR}/inetd.conf \
		${PREFIX}/share/heimdal/examples/inetd.conf.sample
	${INSTALL_DATA} ${FILESDIR}/services \
		${PREFIX}/share/heimdal/examples/services.sample
	# working dir
	${MKDIR} /var/heimdal

.include "../../mk/bsd.pkg.mk"

CONFIGURE_ENV+=	INSTALL_PROGRAM=
