#	$NetBSD: Makefile,v 1.9.8.1 2000/10/17 19:50:31 tv Exp $

PROG=	tcpdchk
SRCS=	tcpdchk.c fakelog.c inetcf.c scaffold.c percent_m.c
MAN=	tcpdchk.8
LDADD+=	-L${.CURDIR}/../../lib/libwrap \
	-L${.CURDIR}/../../lib/libwrap/obj \
	-L/usr/local/v6/lib
LDADD+=	-lwrap
DPADD+=	${.CURDIR}/../../lib/libwrap/libwrap.a \
	${.CURDIR}/../../lib/libwrap/obj/libwrap.a \
	/usr/local/v6/lib/libwrap.a
#DPADD=	${LIBWRAP}

CPPFLAGS+= -I${.CURDIR}/../../lib/libwrap

.include "${.CURDIR}/../../lib/libwrap/Makefile.cflags"

.include <bsd.prog.mk>
