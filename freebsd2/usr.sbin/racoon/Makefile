.if exists(/usr/local/lib/libcrypto.a) || exists(/usr/local/ssl/lib/libcrypto.a)
SUBDIR+=racoon
#SUBDIR+=kmpstat
OPENSSLVER!=    openssl version
.if defined(OPENSSLVER) && ${OPENSSLVER} == "OpenSSL 0.9.5a 1 Apr 2000"
SUBDIR+=racoon
#SUBDIR+=kmpstat
.else
SUBDIR=
all:
	@echo "===> Please use OpenSSL 0.9.5a."
.endif
.else
SUBDIR=

all:
	@echo "===> usr.sbin/racoon is not compiled as you do not have "
	@echo "     SSLeay/OpenSSL on the system."
.endif

.include <bsd.subdir.mk>
