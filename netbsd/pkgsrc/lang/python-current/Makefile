# $NetBSD: Makefile,v 1.18 2000/01/09 01:19:11 wiz Exp $
#

DISTNAME=	Python-1.6b1
PKGNAME=	python-1.6b1
CATEGORIES=	lang
EXTRACT_SUFX=	.tgz

PATCHFILES=	python-16b1-v6-20000815.diff.gz
PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@kame.net
HOMEPAGE=	http://www.python.org/
HOMEPAGE_AGREEMENT=	http://www.python.org/1.6/download.html

FIND?=		/usr/bin/find

PLIST_SRC=	${WRKDIR}/.PLIST_SRC

DIST_SUBDIR=	python

WRKSRC=		${WRKDIR}/Python-1.6b1
GNU_CONFIGURE=	yes

# Make sure having environment variable OPT doesn't affect the
# installed module-building Makefile
#MAKE_ENV+=	'OPT=${CFLAGS}'
#CONFIGURE_ENV+=	'OPT=${CFLAGS}'
#SCRIPTS_ENV+=	'OPT=${CFLAGS}'

# Handle the module setup file:
#   - disable a few broken modules on 64 bit platforms (nothing important)
#   - handle machines with no dynamic loader

.include "../../mk/bsd.prefs.mk"

.if ${MACHINE_ARCH} == "alpha" || ${MACHINE_ARCH} == "sparc64"
NO64BIT=\#
.endif
.if ${MACHINE_ARCH} == "sparc64"
NOSHARED=\#
.endif
.if ${OPSYS} == "SunOS"
ZOULARIS?=	${PREFIX}/bsd
MODADD=		-I${ZOULARIS}/include -L${ZOULARIS}/lib -R${ZOULARIS}/lib
.endif

pre-fetch:
	@if test ! -f ${_DISTDIR}/${DISTNAME}${EXTRACT_SUFX}; then \
		${ECHO_MSG} "===> you must fetch ${DISTNAME}${EXTRACT_SUFX} manually from:"; \
		${ECHO_MSG} "     ${HOMEPAGE_AGREEMENT}"; \
		exit 1; \
	fi

post-configure:
	${SED}  -e 's,@NO64BIT@,${NO64BIT},g' \
		-e 's,@NOSHARED@,${NOSHARED},g' \
		-e 's,@MODADD@,${MODADD},g' \
		${FILESDIR}/Setup >${WRKSRC}/Modules/Setup

post-install:
	${CAT} ${PKGDIR}/PLIST.pre >${PLIST_SRC}
	(cd ${PREFIX}; ${FIND} lib/python1.6 -type f -print >>${PLIST_SRC})
	(cd ${PREFIX}; ${FIND} include/python1.6 -type f -print \
		>>${PLIST_SRC})
	(cd ${PREFIX}; ${FIND} -d include/python1.6 -type d -print | \
		${SED} -e "s/^/@dirrm /" >>${PLIST_SRC})
	${ECHO} "@unexec ${RM} -rf %D/lib/python1.6" >>${PLIST_SRC}
	# Reinstall Python binary to get it stripped
	${RM} ${PREFIX}/bin/python ${PREFIX}/bin/python1.6
	${INSTALL_PROGRAM} ${WRKSRC}/python ${PREFIX}/bin
	${LN} ${PREFIX}/bin/python ${PREFIX}/bin/python1.6

.include "../../mk/bsd.pkg.mk"
