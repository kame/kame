.if exists(/usr/local/lib/libcrypto.a) || exists(/usr/local/ssl/lib/libcrypto.a)
SUBDIR+=racoon kmpstat eaytest
OPENSSLVER!=    openssl version
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
	@echo "     SSLeay/OpenSSL on the system."
.endif

.include <bsd.subdir.mk>
