#	$NetBSD: Makefile,v 1.30 1999/02/18 21:22:51 scottr Exp $
#	@(#)Makefile	8.2 (Berkeley) 4/4/94

PROG=	ftpd
SRCS=	conf.c ftpd.c ftpcmd.y logwtmp.c popen.c util.c
CPPFLAGS+=-DHASSETPROCTITLE
DPADD+=	${LIBCRYPT}
LDADD+=	-lcrypt
MAN=	ftpd.8
MLINKS+=ftpd.8 ftpd.conf.5
.PATH:	${.CURDIR}/../../usr.bin/ftp ${.CURDIR}/../../usr.bin/login

CPPFLAGS+=-DINET6
LDADD+= -L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
.include <bsd.own.mk>

.ifdef SKEY
CPPFLAGS+=-DSKEY
DPADD+= ${LIBSKEY}
LDADD+= -lskey
.endif

.include <bsd.prog.mk>

# XXX Work-around a compiler bug for now... can't use -O
.if (${MACHINE_ARCH} == "powerpc")
COPTS+=-O0
.endif
