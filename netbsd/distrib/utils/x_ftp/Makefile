# $NetBSD: Makefile,v 1.3.2.1 1999/06/25 01:21:52 cgd Exp $
# Build a smaller ftp (i.e. for boot media)

PROG=	ftp
MKMAN=	no

# Need -lutil for: fparseln
CPPFLAGS+= -DHAVE_TIMEGM        # system has timegm(3), a UTC version of mktime
DPADD= ${LIBEDIT} ${LIBTERMCAP} ${LIBUTIL}
LDADD= -ledit -ltermcap -lutil

SRCDIR= ${.CURDIR}/../../../usr.bin/ftp

SRCS=	cmds.c cmdtab.c complete.c domacro.c fetch.c ftp.c main.c ruserpass.c \
	util.c

CPPFLAGS+= -DNO_EDITCOMPLETE -DNO_ABOUT -I${SRCDIR}

all: ${PROG}

CPPFLAGS+= -DINET6
LDADD+= -L${.CURDIR}/../../../lib/libinet6 \
        -L${.CURDIR}/../../../lib/libinet6/obj \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../../lib/libinet6/libinet6.a \
        ${.CURDIR}/../../../lib/libinet6/obj/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>

.PATH:  ${SRCDIR}
