# New ports collection makefile for:    apache HTTPD
# Version required:     1.3*
# Date created:         Fri Aug 25 16:42:36 CDT 1995
# Whom:                 ache@nagual.pp.ru
#
# $Id: Makefile,v 1.1.1.1 1999/08/17 09:09:18 itojun Exp $
#

DISTNAME=	apache_1.3.6
PKGNAME=	apache-1.3.6
CATEGORIES=	www
MASTER_SITES=	ftp://www.apache.org/dist/

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	apache-136-v6-19990724.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@kame.net

#
# Set APACHE_PERF_TUNING env. variable to YES to get maximum performance
#

GNU_CONFIGURE=  yes
CONFIGURE_SCRIPT=	configure.v6
CONFIGURE_ARGS= \
		 --sysconfdir=${PREFIX}/etc/apache \
		 --includedir=${PREFIX}/include/apache \
		 --logfiledir=/var/log \
		 --runtimedir=/var/run \
		 --datadir=${PREFIX}/www \
		 --proxycachedir=${PREFIX}/www/proxy \
		 --libexecdir=${PREFIX}/libexec/apache \
		 --without-confadjust \
		 --enable-shared=remain \
		 --enable-module=most \
		 --enable-module=auth_db \
		 --disable-module=auth_dbm

# Currently perl version don't matter
#                 --with-perl=${PERL5}

OPTIM=-DHARD_SERVER_LIMIT=512 \
-DDOCUMENT_LOCATION=\\"${PREFIX}/www/data/\\" \
-DDEFAULT_PATH=\\"/bin:/usr/bin:${PREFIX}/bin\\"

.if defined(APACHE_PERF_TUNING) && ${APACHE_PERF_TUNING} == YES
OPTIM+= -DBUFFERED_LOGS
CFLAGS+= -O6 -fomit-frame-pointer
.endif

CONFIGURE_ENV= OPTIM='${OPTIM}'

MAN1=   htdigest.1 htpasswd.1
MAN8=   apachectl.8 ab.8 apxs.8 httpd.8 logresolve.8 rotatelogs.8

post-patch:
	chmod +x ${WRKSRC}/${CONFIGURE_SCRIPT}

post-install:
	@if [ ! -f ${PREFIX}/etc/rc.d/apache.sh ]; then \
		${ECHO} "Installing ${PREFIX}/etc/rc.d/apache.sh startup file."; \
		${ECHO} "#!/bin/sh" > ${PREFIX}/etc/rc.d/apache.sh; \
		${ECHO} "[ -x ${PREFIX}/bin/apachectl ] && ${PREFIX}/bin/apachectl start > /dev/null && echo -n ' apache'" >> ${PREFIX}/etc/rc.d/apache.sh; \
		chmod 751 ${PREFIX}/etc/rc.d/apache.sh; \
	fi

.include <bsd.port.mk>
