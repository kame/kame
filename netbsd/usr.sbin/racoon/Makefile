.if exists(/usr/pkg/lib/libcrypto.a) || exists(/usr/pkg/lib/libcrypto.so.1.0) || exists(/usr/local/ssl/lib/libcrypto.a)
.if exists(/usr/local/ssl/bin/openssl)
OPENSSLVER!=	/usr/local/ssl/bin/openssl version
.else
OPENSSLVER!=	openssl version
.endif
.if defined(OPENSSLVER) && ${OPENSSLVER} == "OpenSSL 0.9.4 09 Aug 1999"
SUBDIR+=racoon kmpstat eaytest
.else
SUBDIR=
all:
	@echo "===> Please use OpenSSL 0.9.4."
.endif
.else
SUBDIR=

all:
	@echo "===> usr.sbin/racoon is not compiled as you do not have "
	@echo "     OpenSSL 0.9.4 on the system."
.endif

.include <bsd.subdir.mk>
