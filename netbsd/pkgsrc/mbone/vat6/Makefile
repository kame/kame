# $NetBSD: $
#

DISTNAME=               vat6
CATEGORIES=		mbone
MASTER_SITES=		ftp://ftp.ee.lbl.gov/conferencing/vat/alpha-test/
MASTER_SITES=		http://irl.cs.ucla.edu/software/IPv6/ \
			ftp://ftp.cs.tu-berlin.de/pub/local/kbs/tubmik/gsm/
DISTFILES=		${DISTNAME}${EXTRACT_SUFX} ${GSM}${EXTRACT_SUFX}

PATCH_SITES=		http://www.ichiro.org/IPv6/
PATCHFILES=		vat6-netbsdkame-20000316.patch
PATCH_DIST_STRIP=	-p1

MAINTAINER=		ichiro@ichiro.org

DEPENDS+=               tk-8.0.5:../../x11/tk80
#DEPENDS+=		gsm-1.0.10:${PKGSRCDIR}/audio/gsm

NOT_FOR_PLATFORM=	*-*-alpha	# filter.cc compiler error

GSM=			gsm-1.0.10
GSMDIR=			gsm-1.0-pl10
GSMWORK=		${WRKDIR}/${GSMDIR}

GNU_CONFIGURE=          yes
CONFIGURE_ARGS=         --with-gsm=${WRKDIR}/${GSMDIR}
INSTALL_TARGET=         install install-man

pre-patch: gsm-patch

pre-configure:
	cd ${WRKSRC}; ${RM} -f *.o
	cd ${WRKSRC}; ${LOCALBASE}/bin/autoconf
	cd ${WRKDIR}/${GSMDIR}; ${MAKE}

do-install:
	cd ${WRKSRC} ; ${INSTALL_PROGRAM} vat ${PREFIX}/bin/vat6
	cd ${WRKSRC} ; ${INSTALL_DATA} vat.1 ${PREFIX}/man/man1/vat6.1

gsm-patch:
	@for i in ${FILESDIR}/patches-gsm/patch-*; do \
		${PATCH} -d ${WRKDIR}/${GSMDIR} --forward --quiet -E < $$i; \
	done

.include "../../mk/bsd.pkg.mk"
