# New ports collection makefile for: openssh
# Date created:  18 Mar 1999
# Whom:   dwcjr@inethouston.net
#
# $FreeBSD: ports/security/openssh-portable/Makefile,v 1.67 2003/04/13 11:47:23 dinoex Exp $
#

PORTNAME=	openssh
PORTVERSION=	3.6.1p1
CATEGORIES=	security ipv6
MASTER_SITES=	ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/ \
		ftp://carroll.cac.psu.edu/pub/OpenBSD/OpenSSH/portable/
PKGNAMESUFFIX?=	-portable

MAINTAINER=	dinoex@FreeBSD.org
COMMENT=	The portable version of OpenBSD's OpenSSH

MAN1=	sftp.1 ssh-add.1 ssh-agent.1 ssh-keygen.1 ssh-keyscan.1 scp.1 ssh.1
MLINKS=	ssh.1 slogin.1
MAN5=	ssh_config.5 sshd_config.5
MAN8=	sftp-server.8 sshd.8 ssh-keysign.8

CRYPTOLIBS=	-L${OPENSSLLIB} -lcrypto
GNU_CONFIGURE=	yes
USE_PERL5_BUILD=	yes
CONFIGURE_ARGS+=	--prefix=${PREFIX} --with-md5-passwords \
	--with-ldflags='-L/usr/local/v6/lib -linet6'
PRECIOUS=	ssh_config sshd_config \
		ssh_host_key ssh_host_key.pub \
		ssh_host_rsa_key ssh_host_rsa_key.pub \
		ssh_host_dsa_key ssh_host_dsa_key.pub
ETCOLD=		${PREFIX}/etc
ADDME+=		auth2-pam-freebsd.c

.if exists(/usr/include/security/pam_modules.h)
CONFIGURE_ARGS+=	--with-pam
.endif

.if exists(/usr/include/tcpd.h)
CONFIGURE_ARGS+=	--with-tcp-wrappers
.endif

.if !defined(ENABLE_SUID_SSH)
CONFIGURE_ARGS+=	--disable-suid-ssh
.endif

.if defined(OPENSSH_OVERWRITE_BASE)
WITH_OPENSSL_BASE=	yes
PKGNAMESUFFIX=	-overwrite-base
PREFIX=		/usr
MANPREFIX=	${PREFIX}/share
CONFIGURE_ARGS+=	--mandir=${MANPREFIX}/man --localstatedir=/var
EMPTYDIR=	/var/empty
ETCSSH=		/etc/ssh
PLIST_SUB+=	NOTBASE="@comment "
PLIST_SUB+=	BASE=""
PKGMESSAGE=	pkg-message.empty
.else
.if exists(/var/empty)
EMPTYDIR=	/var/empty
.else
EMPTYDIR=	${PREFIX}/empty
.endif
ETCSSH=		${PREFIX}/etc/ssh
PLIST_SUB+=	NOTBASE=""
PLIST_SUB+=	BASE="@comment "
.endif
PLIST_SUB+=	EMPTYDIR=${EMPTYDIR}
CONFIGURE_ARGS+=	--sysconfdir=${ETCSSH}
CONFIGURE_ARGS+=	--with-privsep-path=${EMPTYDIR}

.if defined(BATCH)
EXTRA_PATCHES+=		${FILESDIR}/batch.patch
.endif

post-extract:
.for i in ${ADDME}
	@${CP} ${FILESDIR}/${i} ${WRKSRC}/
.endfor

.if defined(KRB5_HOME) && exists(${KRB5_HOME})
BROKEN=		patch conflicts with 3.5p1
PKGNAMESUFFIX=	-gssapi
GSSAPI_PATCH=	${PORTNAME}-3.4p1-gssapi-20020627.diff
GSSAPI_SITE=	http://www.sxw.org.uk/computing/patches/
MASTER_SITES+=	${GSSAPI_SITE}
DISTFILES=	${EXTRACT_ONLY} ${GSSAPI_PATCH}
EXTRACT_ONLY=	${PORTNAME}-${PORTVERSION}${EXTRACT_SUFX}
EXTRA_PATCHES+=		${FILESDIR}/servconf.c.patch
BUILD_DEPENDS=		autoconf:${PORTSDIR}/devel/autoconf
# USE_AUTOCONF_VER=	252 # broken
CONFIGURE_ARGS+=	--with-kerberos5=${KRB5_HOME}
AUTOCONF=	autoconf
AUTOHEADER=	autoheader

post-patch:
	@${ECHO_MSG} Applying extra patch for GSS-API key-exchange...
	@${PATCH} ${PATCH_DIST_ARGS:S/-p0/-p1/} \
		< ${DISTDIR}/${GSSAPI_PATCH}

pre-configure:
	@${ECHO_MSG} !!!! Warning this option uses autoconf/autoheader !!!
	(cd ${CONFIGURE_WRKSRC} && ${SETENV} ${AUTOCONF_ENV} ${AUTOCONF} \
		${AUTOCONF_ARGS})
	(cd ${CONFIGURE_WRKSRC} && ${SETENV} ${AUTOCONF_ENV} ${AUTOHEADER})
.endif

post-configure:
	${SED} -e 's:__PREFIX__:${PREFIX}:g' \
		${FILESDIR}/sshd.sh > ${WRKSRC}/sshd.sh

pre-install:
.if defined(OPENSSH_OVERWRITE_BASE)
	-${MKDIR} ${EMPTYDIR}
.else
	-${MKDIR} ${PREFIX}/empty
.endif
	if ! pw groupshow sshd; then pw groupadd sshd -g 22; fi
	if ! pw usershow sshd; then pw useradd sshd -g sshd -u 22 \
		-h - -d ${EMPTYDIR} -s /nonexistent -c "sshd privilege separation"; fi
	-@[ ! -d ${ETCSSH} ] && ${MKDIR} ${ETCSSH}
.for i in ${PRECIOUS}
	-@[ -f ${ETCOLD}/${i} ] && [ ! -f ${ETCSSH}/${i} ] && \
		${ECHO_MSG} ">> Linking ${ETCSSH}/${i} from old layout." && \
		${LN} ${ETCOLD}/${i} ${ETCSSH}/${i}
.endfor

post-install:
.if !defined(OPENSSH_OVERWRITE_BASE)
	${INSTALL_SCRIPT} ${WRKSRC}/sshd.sh ${PREFIX}/etc/rc.d/sshd.sh.sample
.endif
	${INSTALL_DATA} -c ${WRKSRC}/ssh_config.out ${ETCSSH}/ssh_config-dist
	${INSTALL_DATA} -c ${WRKSRC}/sshd_config.out ${ETCSSH}/sshd_config-dist
.if !defined(OPENSSH_OVERWRITE_BASE)
	@${CAT} ${PKGMESSAGE}
.endif

test:
	(cd ${WRKSRC}/regress && ${SETENV} ${MAKE_ENV} \
	PATH=${WRKSRC}:${PREFIX}/bin:${PREFIX}/sbin:${PATH} \
	${MAKE} ${MAKE_FLAGS} ${MAKEFILE} ${MAKE_ARGS} )

.include <bsd.port.pre.mk>

.include "${PORTSDIR}/security/openssl/bsd.openssl.mk"
CONFIGURE_ARGS+=	--with-ssl-dir=${OPENSSLBASE}

.include <bsd.port.post.mk>
