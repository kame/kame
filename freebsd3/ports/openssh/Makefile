# New ports collection makefile for:	OpenSSH
# Version required:	19991107
# Date created:		Tue Nov 16 19:45:46 JST 1999
# Whom:			sumikawa
#
# $FreeBSD: ports/security/openssh/Makefile,v 1.12 1999/11/17 20:12:17 green Exp $
# $Id: Makefile,v 1.4 1999/12/27 12:37:11 sumikawa Exp $
#

DISTNAME=	src/usr.bin/ssh
PKGNAME=	OpenSSH-1.2
CATEGORIES=	security net
MASTER_SITES=	anoncvs@anoncvs1.ca.openbsd.org:/cvs \
		:pserver:anoncvs@anoncvs1.usa.openbsd.org:/cvs

PATCH_SITES=	http://www.rcac.tdi.co.jp/fujiwara/
PATCHFILES=	openssh.v6.patch-0.01
PATCH_DIST_STRIP=	-p1

MAINTAINER=	sumikawa@kame.net

LIB_DEPENDS=	crypto.1:${PORTSDIR}/security/openssl

RESTRICTED=	"Links with cryptographic code."

.include <bsd.port.pre.mk>
CAT?=		/bin/cat
DISTFILES!=	${CAT} ${FILESDIR}/distfiles

CVS_CMD?=	cvs -z3
CVS_DATE=	Mon Nov 15 01:30:17 EST 1999
CRYPTOLIBS=	-L${PREFIX}/lib -lcrypto
.if defined(USA_RESIDENT) && ${USA_RESIDENT} == YES
CRYPTOLIBS+=	-lRSAglue -lrsaref
.endif
# Here, MANDIR is concetenated to DESTDIR which all forms the man install dir...
MAKE_ENV=	DESTDIR=${PREFIX} MANDIR=/man/man CRYPTOLIBS="${CRYPTOLIBS}"
.if !exists(/usr/include/tcpd.h)
MAKE_ENV+=	TCP_WRAPPERS=no
.endif
.if defined(AFS) && ${AFS} == YES
MAKE_ENV+=	AFS=yes
.endif
.if defined(KERBEROS) && ${KERBEROS} == YES
MAKE_ENV+=	KERBEROS=yes
.endif
.if defined(SKEY) && ${SKEY} == YES
MAKE_ENV+=	SKEY=yes
.endif
STAMPFILE=	${DISTDIR}/${PKGNAME}/.stamp
WRKSRC=		${WRKDIR}/ssh

do-fetch:
	@if [ ! -e ${STAMPFILE} ] || \
	    [ "X${CVS_DATE}" != "X$$(${CAT} ${STAMPFILE})" ]; then \
		unset CVS_RSH CVS_SERVER || ${TRUE}; \
		if [ -n "${PORTS_CVS_RSH}" ]; then \
			export CVS_RSH="${PORTS_CVS_RSH}"; \
		fi; \
		${MKDIR} ${DISTDIR}/${PKGNAME} && \
		cd ${DISTDIR}/${PKGNAME} || exit; \
		for CVS_SITE in ${MASTER_SITES}; do \
			${ECHO_MSG} ">> Attempting to CVS checkout from\
			$${CVS_SITE}."; \
			${CVS_CMD} -d $${CVS_SITE} co -D "${CVS_DATE}" \
				${DISTNAME} && { ${ECHO} -n ${CVS_DATE} > \
				${STAMPFILE} && exit; }; \
		done; \
		${ECHO_MSG} ">> Couldn't CVS checkout ${PKGNAME}.  Please try\
			to retrieve"; \
		${ECHO_MSG} ">> this port manually into ${_DISTDIR} and try\
			again."; \
		exit 1; \
	fi
	@(cd ${_DISTDIR}; \
	 for file in ${PATCHFILES}; do \
		if [ ! -f $$file -a ! -f `${BASENAME} $$file` ]; then \
			if [ -h $$file -o -h `${BASENAME} $$file` ]; then \
				${ECHO_MSG} ">> ${_DISTDIR}/$$file is a broken symlink."; \
				${ECHO_MSG} ">> Perhaps a filesystem (most likely a CD) isn't mounted?"; \
				${ECHO_MSG} ">> Please correct this problem and try again."; \
				exit 1; \
			fi ; \
			${ECHO_MSG} ">> $$file doesn't seem to exist on this system."; \
			for site in ${PATCH_SITES}; do \
			    ${ECHO_MSG} ">> Attempting to fetch from $${site}."; \
				DIR=${DIST_SUBDIR}; \
				CKSIZE=`${GREP} "^SIZE ($${DIR:+$$DIR/}$$file)" ${MD5_FILE} | ${AWK} '{print $$4}'`; \
				case $${file} in \
				*/*)	${MKDIR} $${file%/*}; \
						args="-o $${file} $${site}$${file}";; \
				*)		args=$${site}$${file};; \
				esac; \
				if ${SETENV} ${FETCH_ENV} ${FETCH_CMD} ${FETCH_BEFORE_ARGS} $${args} ${FETCH_AFTER_ARGS}; then \
					continue 2; \
				fi \
			done; \
			${ECHO_MSG} ">> Couldn't fetch it - please try to retrieve this";\
			${ECHO_MSG} ">> port manually into ${_DISTDIR} and try again."; \
			exit 1; \
	    fi \
	 done)

do-extract:
	@${MKDIR} ${WRKDIR}
	@${CP} -r ${DISTDIR}/${PKGNAME}/${DISTNAME} ${WRKDIR}
	@${CP} ${FILESDIR}/strlcpy.c ${WRKSRC}/lib/

post-patch:
	@${PERL} -pi.orig -e 's:(_PATH_STDPATH):$$1 "${PREFIX}/bin":g' \
		${WRKSRC}/sshd.c
	@${PERL} -pi.orig -e 's:__PREFIX__:${PREFIX}:g' ${WRKSRC}/ssh.h
	@${PERL} -pi.orig -e 's:__PREFIX__:${PREFIX}:g' ${WRKSRC}/sshd_config
	@${PERL} -pi.openssl -e \
		's:^(\s*#\s*include\s+<)ssl(/\w+\.h>\s*)$$:$$1openssl$$2:g' \
		${WRKSRC}/*.[ch]

pre-install:
	@if [ ! -f ${PREFIX}/etc/sshd_config ]; then \
		cd ${WRKSRC} && ${MAKE} DESTDIR=${PREFIX} distribution; \
	else \
		${ECHO} ">> ${PREFIX}/etc/sshd_config exists, not being replaced!"; \
		${ECHO} ">> If this is left over from another version of SSH, you will"; \
		${ECHO} ">> need to update it to work with OpenSSH."; \
	fi

post-install:
	@if [ ! -f ${PREFIX}/etc/rc.d/sshd.sh ]; then \
		${ECHO} ">> Installing ${PREFIX}/etc/rc.d/sshd.sh startup file."; \
		${ECHO} "#!/bin/sh" > ${PREFIX}/etc/rc.d/sshd.sh; \
		${ECHO} "[ -x ${PREFIX}/sbin/sshd ] && ${PREFIX}/sbin/sshd &&" \
			"${ECHO} -n ' sshd'" >> ${PREFIX}/etc/rc.d/sshd.sh; \
		${CHMOD} 755 ${PREFIX}/etc/rc.d/sshd.sh; \
	fi

.include <bsd.port.mk>
