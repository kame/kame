# New ports collection makefile for:    XFree86
# Version required:     3.3.3
# Date created:         5 January 1995
# Whom:                 jmz
#
# $Id: Makefile,v 1.1 1999/08/17 09:09:11 itojun Exp $
#

DISTNAME=	xc
PKGNAME= 	XFree86-v6-3.3.3
CATEGORIES=	x11
# For people in Japan...
MASTER_SITES=	ftp://ftp.iij.ad.jp/pub/X/XFree86/3.3.3/source/ \
		ftp://ftp.kame.net/pub/inria/x11/
# For other cases...
#MASTER_SITES=
# For v6 capable X11.
MASTER_SITES+=	ftp://ftp.inria.fr/network/ipv6/x11/ \
		ftp://ftp.kame.net/pub/inria/x11/
# XFree master sites.
MASTER_SITES+=	ftp://ftp.xfree86.org/pub/XFree86/3.3.2/source/ \
		ftp://xfree86.cdrom.com/pub/XFree86/3.3.2/source/ \
		ftp://ftp.ibp.fr/pub/X11/XFree86/XFree86-3.3.2/source/ \
		ftp://ftp.uni-stuttgart.de/pub/X11/Xfree86/3.3.2/source/ \
		ftp://sunsite.doc.ic.ac.uk/packages/XFree86/3.3.2/source/
DISTFILES=	X333src-1.tgz X333src-2.tgz X11-990224.tgz

MAINTAINER=	itojun@kame.net

IS_INTERACTIVE=	yes	# configure script asks questions
NO_PACKAGE=	package available from XFree86
USE_X11=	yes
ALL_TARGET=	World
INSTALL_TARGET=	install install.man
DIST_SUBDIR=	xc

.if defined(XDM_DES) && (${USA_RESIDENT} != YES && ${USA_RESIDENT} != NO)
pre-fetch:
	@${ECHO}
	@${ECHO} You must set variable USA_RESIDENT to YES or NO.
	@false
.elif defined(USA_RESIDENT)
.if ${USA_RESIDENT} == NO
pre-fetch:
MASTER_SITES+=	ftp://psych.psy.uq.oz.au/pub/X11R5/ \
		ftp://ftp.internat.freebsd.org/pub/FreeBSD/X11-Crypto/ \
		ftp://ftp3.za.freebsd.org/pub/FreeBSD/X11-Crypto/
DISTFILES+=	Wraphelp.c
IGNOREFILES=	Wraphelp.c
.endif
.if ${USA_RESIDENT} == YES
pre-fetch:
	@${ECHO}
	@${ECHO} Assuming that you have fetched a USA-Legal Wraphelp.c.
.endif
.endif

PATCHV6=config/cf/host.def \
	lib/SM/sm_genid.c \
	lib/X11/ConnDis.c \
	lib/X11/Imakefile \
	lib/Xau/AuGetBest.c \
	lib/Xau/Imakefile \
	lib/Xmu/CvtStdSel.c \
	lib/xtrans/Xtrans.c \
	lib/xtrans/Xtranssock.c \
	lib/xtrans/Xtransutil.c \
	programs/Xserver/os/access.c \
	programs/Xserver/os/connection.c \
	programs/Xserver/os/k5auth.c \
	programs/Xserver/os/utils.c \
	programs/Xserver/os/xdmcp.c \
	programs/lbxproxy/os/connection.c \
	programs/xauth/gethost.c \
	programs/xauth/parsedpy.c \
	programs/xauth/xauth.c \
	programs/xdm/access.c \
	programs/xdm/auth.c \
	programs/xdm/choose.c \
	programs/xdm/chooser.c \
	programs/xdm/dm.c \
	programs/xdm/netaddr.c \
	programs/xdm/socket.c \
	programs/xdm/xdmcp.c \
	programs/xfs/difs/main.c \
	programs/xfs/os/access.c \
	programs/xfwp/xfwp.c \
	programs/xfwp/xfwp.h \
	programs/xfwp/xfwp.man \
	programs/xhost/xhost.c

post-patch:
	for i in ${PATCHV6}; do \
		/bin/cp -f ${WRKSRC}/$$i-new ${WRKSRC}/$$i; \
	done

pre-install:
	${MKDIR} /usr/X11R6
post-install:
	${LDCONFIG} -m ${PREFIX}/lib

.include <bsd.port.mk>
