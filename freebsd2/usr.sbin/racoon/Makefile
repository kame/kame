.if exists(/usr/local/lib/libcrypto.a) || exists(/usr/local/ssl/lib/libcrypto.a)
SUBDIR+=racoon kmpstat eaytest
.else
SUBDIR=
.endif

.include <bsd.subdir.mk>
