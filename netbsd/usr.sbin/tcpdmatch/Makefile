#	$NetBSD: Makefile,v 1.8 1998/03/05 18:23:31 christos Exp $
#

PROG=	tcpdmatch
SRCS=	tcpdmatch.c fakelog.c inetcf.c scaffold.c percent_m.c
MAN=	tcpdmatch.8
TCPDCHK=${.CURDIR}/../tcpdchk
.PATH: ${TCPDCHK}
CPPFLAGS+= -I${TCPDCHK} -I${.CURDIR}/../../lib/libwrap
LDADD+=	-L${.CURDIR}/../../lib/libwrap \
	-L${.CURDIR}/../../lib/libwrap/obj \
	-L/usr/local/v6/lib
LDADD+=	-lwrap
DPADD+=	${.CURDIR}/../../lib/libwrap/libwrap.a \
	${.CURDIR}/../../lib/libwrap/obj/libwrap.a \
	/usr/local/v6/lib/libwrap.a
#DPADD=	${LIBWRAP}

.include "${.CURDIR}/../../lib/libwrap/Makefile.cflags"

.include <bsd.prog.mk>
