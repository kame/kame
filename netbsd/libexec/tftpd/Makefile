#	$NetBSD: Makefile,v 1.7 1997/10/22 06:03:55 lukem Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/4/93

PROG=	tftpd
SRCS=	tftpd.c tftpsubs.c
MAN=	tftpd.8
CPPFLAGS+=-I${.CURDIR}/../../usr.bin/tftp
.PATH:	${.CURDIR}/../../usr.bin/tftp

# for portability across old sockaddr_storage definition
CPPFLAGS+=-Dss_len=__ss_len -Dss_family=__ss_family

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
