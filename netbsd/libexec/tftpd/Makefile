#	$NetBSD: Makefile,v 1.8 1999/07/12 20:17:09 itojun Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/4/93

PROG=	tftpd
SRCS=	tftpd.c tftpsubs.c
MAN=	tftpd.8
CPPFLAGS+=-I${.CURDIR}/../../usr.bin/tftp
.PATH:	${.CURDIR}/../../usr.bin/tftp

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
