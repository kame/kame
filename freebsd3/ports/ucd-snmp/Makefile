# New ports collection makefile for:	ucd-snmp-v6
# Version required:			3.5.3 + IPv6 981231
# Date created:				26 June 1996
# Whom:					itojun@iijlab.net
#
# $Id: Makefile,v 1.1.1.1 1999/08/17 09:10:48 itojun Exp $
#

DISTNAME=	ucd-snmp-3.6.1
PKGNAME=	ucd-snmp-v6-3.6.1.19990406
CATEGORIES=	net
MASTER_SITES= 	ftp://ucd-snmp.ucdavis.edu/ \
		ftp://sunsite.cnlab-switch.ch/mirror/ucd-snmp/ \
		ftp://ftp.win.or.jp/pub/network/snmp/ucd-snmp/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	ucd-snmp-3.6.1-v6-19990406.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@iijlab.net

BROKEN=		"not buildable - maybe forgot commits?"

CONFIGURE_ARGS+=	--enable-shared
CONFIGURE_ARGS+=	--enable-ipv6

USE_CONFIGURE=	YES
GNU_CONFIGURE=	YES
.if defined(BATCH)
CONFIGURE_ARGS+= --with-defaults --with-sys-contact=nobody@no.where
.else
IS_INTERACTIVE= yes
.endif

MAN1=		snmpbulkwalk.1 snmpd.1 snmpdelta.1 snmpget.1 snmpgetnext.1 \
		snmpnetstat.1 snmpset.1 snmpstatus.1 snmptable.1 snmptest.1 \
		snmptranslate.1 snmptrap.1 snmpwalk.1 snmpcmd.1
MAN3=		mib_api.3 snmp_api.3
MAN5=		snmpd.conf.5 variables.5
MAN8=		snmptrapd.8
BIN=		snmpbulkwalk snmpget snmpgetnext snmpnetstat snmpset \
		snmpstatus snmptest snmptranslate snmptrap snmpwalk
SBIN=		snmpd snmptrapd

post-install:
	( cd ${PREFIX}/bin; strip ${BIN} )
	( cd ${PREFIX}/sbin; strip ${SBIN} )
#	if [ -f ${PREFIX}/lib/libsnmp.so.3.6 ]; then \
#		/bin/rm ${PREFIX}/lib/libsnmp.so.3.6; \
#	fi
#	( cd ${PREFIX}/lib && ${LN} libsnmp.so libsnmp.so.3.6 )
	@${MKDIR} ${PREFIX}/share/examples/ucd-snmp
	@for F in ${WRKSRC}/etc/* ; do \
		${INSTALL_DATA} $$F ${PREFIX}/share/examples/ucd-snmp ; done
	@if [ ! -f ${PREFIX}/etc/rc.d/snmpd.sh ]; then \
		echo "Creating ${PREFIX}/etc/rc.d/snmpd.sh startup file."; \
		echo "#!/bin/sh" > ${PREFIX}/etc/rc.d/snmpd.sh; \
		echo "[ -x ${PREFIX}/sbin/snmpd ] && ${PREFIX}/sbin/snmpd && echo -n ' snmpd'" >> ${PREFIX}/etc/rc.d/snmpd.sh; \
		chmod 751 ${PREFIX}/etc/rc.d/snmpd.sh; \
	 fi

.include <bsd.port.mk>
