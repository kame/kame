.include <bsd.own.mk>			# for configuration variables.

SUBDIR=	lib
#SUBDIR=	lib libexec sbin usr.bin usr.sbin share

includes:
	(cd ${.CURDIR}/include; $(MAKE))
install-includes:
	(cd ${.CURDIR}/include; $(MAKE) install)

.include <bsd.subdir.mk>
.include "../Makefile.inc"
