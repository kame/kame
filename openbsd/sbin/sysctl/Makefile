#	$OpenBSD: Makefile,v 1.7 2000/04/14 02:40:01 itojun Exp $

PROG=	sysctl
MAN=	sysctl.8

CPPFLAGS+=-DINET6

#afterinstall:
#	(cd ${DESTDIR}/usr/sbin; ln -sf ../../sbin/sysctl .)

.include <bsd.prog.mk>

.if (${UVM:L} == "yes")
CFLAGS+=-DUVM
.endif
