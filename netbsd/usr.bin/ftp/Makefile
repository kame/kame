#	$NetBSD: Makefile,v 1.23 1999/12/12 02:14:53 lukem Exp $
#	from: @(#)Makefile	8.2 (Berkeley) 4/3/94

PROG=	ftp
SRCS=	cmds.c cmdtab.c complete.c domacro.c fetch.c ftp.c main.c ruserpass.c \
	util.c

# Uncomment the following to provide defaults for gate-ftp operation
#
#CPPFLAGS+=-DGATE_SERVER=\"ftp-gw.host\" # -DGATE_PORT=21

CPPFLAGS+=	-DNO_EDITCOMPLETE -DNO_QUAD

LDADD+=	-ledit -ltermcap -lutil
DPADD+=	${LIBEDIT} ${LIBTERMCAP} ${LIBUTIL}

CPPFLAGS+= -DINET6
.if exists(/usr/local/v6/lib/libinet6.a)
LDADD+= -L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
.endif

cmds.o fetch.o: version.h
main.o:	ftp_var.h

.include <bsd.prog.mk>
