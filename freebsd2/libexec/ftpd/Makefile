#	@(#)Makefile	8.2 (Berkeley) 4/4/94
#	$Id: Makefile,v 1.17.2.4 1998/03/05 12:21:16 jkh Exp $

PROG=	ftpd
MAN8=	ftpd.8
SRCS=	ftpd.c ftpcmd.c logwtmp.c popen.c skey-stuff.c

#CFLAGS+=-DSETPROCTITLE -DSKEY -DLOGIN_CAP -DVIRTUAL_HOSTING -Wall
CFLAGS+=-DSETPROCTITLE -DSKEY -DLOGIN_CAP -DVIRTUAL_HOSTING
CFLAGS+=-DINET6

LDADD=	-L${.CURDIR}/../../lib/libskey \
	-L${.CURDIR}/../../lib/libskey/obj \
	-L/usr/local/v6/lib
LDADD+=	-lskey -lmd -lcrypt -lutil
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD=	${LIBSKEY} ${LIBMD} ${LIBCRYPT} ${LIBUTIL}
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

CLEANFILES+=ftpcmd.c y.tab.h

.ifdef FTPD_INTERNAL_LS
LSDIR=	../../bin/ls
.PATH:	${.CURDIR}/${LSDIR}
SRCS+=	ls.c cmp.c print.c stat_flags.c util.c
CFLAGS+=-DINTERNAL_LS -Dmain=ls_main -I${.CURDIR}/${LSDIR}
.endif

.if exists(${DESTDIR}/usr/lib/libkrb.a) && defined(MAKE_KERBEROS4)
.PATH:  ${.CURDIR}/../../usr.bin/login
SRCS+=	klogin.c
LDADD+=	-lkrb -ldes
DPADD+= ${LIBKRB} ${LIBDES}
CFLAGS+=-DKERBEROS
DISTRIBUTION=	krb
.endif

.include <bsd.prog.mk>
