.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

SUBDIR=	man4

makedb:
	/usr/libexec/makewhatis ${DESTDIR}/usr/share/man

.include <bsd.subdir.mk>
