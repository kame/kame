.if exists(/usr/pkg/lib/libcrypto.a) || exists(/usr/pkg/lib/libcrypto.so.1.0) || exists(/usr/local/ssl/lib/libcrypto.a)
SUBDIR+=racoon kmpstat eaytest
.else
SUBDIR=

all:
	@echo "===> usr.sbin/racoon is not compiled as you do not have "
	@echo "     SSLeay/OpenSSL on the system."
.endif

.include <bsd.subdir.mk>
