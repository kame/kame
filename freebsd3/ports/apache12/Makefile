# New ports collection makefile for:    apache HTTPD
# Version required:     1.2.6
# Date created:         Fri Aug 25 16:42:36 CDT 1995
# Whom:                 erich@rrnet.com
#
# $Id: Makefile,v 1.1.1.1 1999/08/17 09:09:14 itojun Exp $
#

DISTNAME=       apache_1.2.6
PKGNAME=        apache-1.2.6
CATEGORIES=	www
MASTER_SITES=   ftp://www.apache.org/apache/dist/

#.if defined(PATCH_DEBUG)
#PATCH_DIST_ARGS= -d ${WRKSRC}/src -E ${PATCH_DIST_STRIP}
#.else
#PATCH_DIST_ARGS= -d ${WRKSRC}/src --forward --quiet -E ${PATCH_DIST_STRIP}
#.endif

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	apache-126-v6-981002.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=     itojun@kame.net

MAN1=		htpasswd.1
MAN8=		httpd.8
DOCDIR=		${PREFIX}/share/doc/apache

# Set it for local-supplied patch, f.e.
# VERS_ID = mods-1.0/me

.if defined(VERS_ID)
post-patch:
	@cd ${WRKSRC}/src && \
	${MV} Configuration Configuration.old && \
	${SED} 's;^#*OPTIM=.*;OPTIM= -DSERVER_SUBVERSION=\\"${VERS_ID}\\";' \
	< Configuration.old > Configuration
.endif

post-install:
	@if [ ! -f ${PREFIX}/etc/rc.d/apache.sh ]; then \
		${ECHO} "Installing ${PREFIX}/etc/rc.d/apache.sh startup file."; \
		${SED} 's;PREFIX;${PREFIX};' < ${FILESDIR}/apache.sh.tmpl > \
		${PREFIX}/etc/rc.d/apache.sh; \
		chmod 751 ${PREFIX}/etc/rc.d/apache.sh; \
	fi
.for i in ${MAN1}
	${INSTALL_MAN} ${WRKSRC}/support/$i ${PREFIX}/man/man1
.endfor
.for i in ${MAN8}
	${INSTALL_MAN} ${WRKSRC}/support/$i ${PREFIX}/man/man8
.endfor
.if !defined(NOPORTDOCS)
	${MKDIR} ${DOCDIR}
.for i in README LICENSE ABOUT_APACHE
	${INSTALL_DATA} ${WRKSRC}/$i ${DOCDIR}
.endfor
	@cd ${WRKSRC}/htdocs; tar cf - . | (cd ${DOCDIR}; tar xf -)
.endif

.include <bsd.port.mk>
