.if exists(/usr/local/lib/libcrypto.a) || exists(/usr/local/ssl/lib/libcrypto.a) || exists(/usr/lib/libcrypto.a)
SUBDIR+=racoon kmpstat
.else
SUBDIR=

all:
	@echo "===> usr.sbin/racoon is not compiled as you do not have "
	@echo "     SSLeay/OpenSSL on the system."
.endif

.include <bsd.subdir.mk>
