# New ports collection makefile for:	ucd-snmp-v6
# Version required:			4.0.1 + IPv6 19991021
# Date created:				26 June 1996
# Whom:					itojun@iijlab.net
#
# $Id: Makefile,v 1.4 1999/10/27 01:14:23 itojun Exp $
#

DISTNAME=	ucd-snmp-4.0.1
PKGNAME=	ucd-snmp-v6-4.0.1.19991021
CATEGORIES=	net
MASTER_SITES= 	ftp://ucd-snmp.ucdavis.edu/ \
		ftp://sunsite.cnlab-switch.ch/mirror/ucd-snmp/ \
		ftp://ftp.win.or.jp/pub/network/snmp/ucd-snmp/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	ucd-snmp-4.0.1-v6-19991021.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@iijlab.net

#CONFIGURE_ARGS+=	--enable-shared
CONFIGURE_ARGS+=	--enable-ipv6

USE_CONFIGURE=	YES
GNU_CONFIGURE=	YES
.if defined(BATCH)
CONFIGURE_ARGS+= --with-defaults --with-sys-contact=nobody@no.where
.else
IS_INTERACTIVE= yes
.endif

MAN1=	snmpdelta.1 snmpcmd.1 snmpd.1 snmptable.1 snmptranslate.1 \
	snmpbulkwalk.1 snmpwalk.1 snmpusm.1 snmptrap.1 snmpstatus.1 \
	snmpnetstat.1 snmpget.1 snmpset.1 snmptest.1 snmpgetnext.1
MAN3=	read_config.3 mib_api.3 snmp_api.3 snmp_sess_api.3
MAN5=	snmptrapd.conf.5 snmpd.conf.5 snmp.conf.5 snmp_config.5 variables.5
MAN8=	snmptrapd.8
BIN=	encode_keychange snmptest snmpdelta snmpstatus \
	snmptranslate snmptrap snmptable snmpbulkwalk snmpwalk snmpusm \
	snmpset snmpgetnext snmpget snmpnetstat
SBIN=	snmpd snmptrapd

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
