#	$NetBSD: Makefile,v 1.12.10.1 2000/10/18 04:21:20 tv Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 7/19/93

PROG=	rsh

CPPFLAGS+= -DINET6
DPADD+=	${LIBEDIT} ${LIBTERMCAP}

LDADD+= -L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

#CPPFLAGS+=-DKERBEROS -DCRYPT
#SRCS=	rsh.c krcmd.c kcmd.c des_rw.c
#DPADD=	${LIBKRB} ${LIBDES}
#LDADD=	-lkrb -ldes
.PATH:	${.CURDIR}/../rlogin
BINOWN= root
BINMODE=4555

.include <bsd.prog.mk>
