# New ports collection makefile for:    python
# Version required:     1.5.2
# Date created:         08 August 1995
# Whom:                 jkh
#
# $Id: Makefile,v 1.2 1999/12/27 02:11:01 sumikawa Exp $
# $FreeBSD: ports/lang/python/Makefile,v 1.55 1999/11/03 09:45:25 tg Exp $
#

DISTNAME=       py152
PKGNAME=        python-1.5.2
CATEGORIES=	lang python tk80
# if you use ports-current, enable this line
#CATEGORIES=	lang python tk82
MASTER_SITES=	ftp://www.python.org/pub/python/src/ \
		ftp://ftp.cwi.nl/pub/python/src/
EXTRACT_SUFX=	.tgz

PATCH_SITES=	ftp://ftp.kame.net/pub/kame/misc/
PATCHFILES=	python-152-v6-19990420.diff.gz
PATCH_DIST_STRIP=	-p1

MAINTAINER=	itojun@kame.net

LIB_DEPENDS=	${TK_DEPENDS}

DIST_SUBDIR=	python
WRKSRC=		${WRKDIR}/Python-1.5.2
GNU_CONFIGURE=	yes
CONFIGURE_ARGS=	--with-fpectl --with-libs='-lxpg4'
CONFIGURE_ENV=	OPT="${CFLAGS}"
INSTALL_TARGET=	install
PLIST=		${WRKDIR}/PLIST
MAN1=		python.1

#
# The standard setup file
#
SETUP_FILE=	Setup

#
# Support for Tk is compiled in by default.
#
WITH_TK?=	yes
.if defined(WITH_TK) && $(WITH_TK) == yes
TK_DEPENDS=	tk80.1:${PORTSDIR}/x11-toolkits/tk80
# if you use ports-current, enable this line
#TK_DEPENDS=	tk82.1:${PORTSDIR}/x11-toolkits/tk82
SETUP_LOCAL=	Setup.tk
PLIST_TK=	${PKGDIR}/PLIST.tk
.endif

#
# If you want to use Python's thread module, you need to set WITH_THREADS
# to 'yes', and you must have the FreeBSD threading c library (libc_r)
# installed. See 'man 3 pthread' for details on libc_r.
#
# This option is enabled by default.
#
WITH_THREADS?=	yes
LIBC_R!=	/sbin/ldconfig -r | grep c_r || true
.if ${LIBC_R} != "" && defined(WITH_THREADS) && ${WITH_THREADS} == yes
CONFIGURE_ARGS+=	--with-thread
CFLAGS+=		-D_THREAD_SAFE
CONFIGURE_ENV+=		LDFLAGS="-pthread ${LDFLAGS}"
.endif

#
# The mpz module is built on machines with a full source tree
#
.if exists(/usr/src/contrib/libgmp/gmp-impl.h)
SETUP_LOCAL+=	Setup.gmp
PLIST_GMP=	${PKGDIR}/PLIST.gmp
.endif

#
# Install the Tools by default. It contains scripts ranging from an IDE
# to a web tree checker, to a collection of simple scripts that are useful
# while extending or managing Python.
#
WITH_TOOLS?=	yes
.if defined(WITH_TOOLS) && ${WITH_TOOLS} == yes
PLIST_TOOLS=	${PKGDIR}/PLIST.Tools
.endif

post-extract:
	cd ${WRKSRC}/Lib && ${SH} ${FILESDIR}/plat-freebsd4.sh

post-configure:
	${CP} ${FILESDIR}/${SETUP_FILE} ${WRKSRC}/Modules/Setup
.for file in ${SETUP_LOCAL}
	${CAT} ${FILESDIR}/${file} >> ${WRKSRC}/Modules/Setup.local
.endfor

.include <bsd.port.pre.mk>

.if ${OSVERSION} >= 400000
PLATFORMS=plat-freebsd2 plat-freebsd3
.elif ${OSVERSION} >= 300000
PLATFORMS=plat-freebsd2 plat-freebsd4
.else   
PLATFORMS=plat-freebsd3 plat-freebsd4
.endif

pre-install:
.for platform in ${PLATFORMS}
	${MKDIR} ${PREFIX}/lib/python1.5/${platform}
	${INSTALL_DATA} ${WRKSRC}/Lib/${platform}/*                    \
		${PREFIX}/lib/python1.5/${platform}/
.endfor
	@sort -r -o ${PLIST} ${PLIST_TK} ${PLIST_GMP} ${PLIST_TOOLS} ${PKGDIR}/PLIST

post-install:
	strip ${PREFIX}/bin/python
	@${MKDIR} ${PREFIX}/share/doc/python
	${INSTALL_DATA} ${WRKSRC}/Misc/COPYRIGHT ${PREFIX}/share/doc/python
	@${MKDIR} ${PREFIX}/lib/python1.5/site-packages
.if defined(WITH_TOOLS) && ${WITH_TOOLS} == yes
	@cd ${WRKSRC}; tar cf - Tools | \
		(cd ${PREFIX}/lib/python1.5; tar xf -)
.endif

.include <bsd.port.post.mk>
