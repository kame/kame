.if exists(/usr/pkg/lib/libcrypto.a) || exists(/usr/pkg/lib/libcrypto.so.1.0) || exists(/usr/local/ssl/lib/libcrypto.a)
SUBDIR+=racoon kmpstat eaytest
.else
SUBDIR=
.endif

.include <bsd.subdir.mk>
