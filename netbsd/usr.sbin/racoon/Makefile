.if exists(/usr/pkg/lib/libcrypto.a) || exists(/usr/pkg/lib/libcrypto.so)
SUBDIR+=racoon kmpstat eaytest
.else
SUBDIR=
.endif

.include <bsd.subdir.mk>
