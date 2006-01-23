#	$NetBSD: Makefile,v 1.39 2003/12/13 22:07:35 chs Exp $
#	from: @(#)Makefile	8.2 (Berkeley) 12/15/93

.include <bsd.own.mk>

MAN=	telnetd.8

CPPFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-L${.CURDIR}/../../lib/libtelnet -L${.CURDIR}/../../lib/libtelnet/obj \
	-L/usr/local/v6/lib -ltelnet
DPADD+=	${.CURDIR}/../../lib/libtelnet/libtelnet.a \
	${.CURDIR}/../../lib/libtelnet/obj/libtelnet.a \
	/usr/local/v6/lib/libtelnet.a

PROG=	telnetd
CPPFLAGS+=-DLINEMODE -DKLUDGELINEMODE -DDIAGNOSTICS -I${LIBTELNETDIR}/..
CPPFLAGS+=-DOLD_ENVIRON -DENV_HACK -DSECURELOGIN -DSUPPORT_UTMP -DSUPPORT_UTMPX
SRCS=	authenc.c global.c slc.c state.c sys_term.c telnetd.c \
	termstat.c utility.c
DPADD=	${LIBUTIL} ${LIBTERMCAP} ${LIBTELNETDIR}/libtelnet.a
LDADD+=	-lutil -ltermcap ${LIBTELNETDIR}/libtelnet.a

CPPFLAGS+=-I${NETBSDSRCDIR}/lib
CPPFLAGS+=-I${.CURDIR}

LIBTELNETDIR!=	cd ${.CURDIR}/../../lib/libtelnet; ${PRINTOBJDIR}

.if (${USE_KERBEROS} != "no")
CPPFLAGS+=-I${DESTDIR}/usr/include/krb5
CPPFLAGS+=-DKRB5 -DAUTHENTICATION -DENCRYPTION
LDADD+= -lkrb5 -lasn1 -lcrypto
DPADD+=	${LIBKRB5} ${LIBASN1} ${LIBCRYPTO}

.if (${USE_KERBEROS4} != "no")
CPPFLAGS+=-DKRB4
LDADD+= -lkrb -ldes
DPADD+=	${LIBKRB} ${LIBDES}
.endif

VERS!=	cd ${NETBSDSRCDIR}/lib/libvers && ${PRINTOBJDIR}

LDADD+=	 -lcom_err -L${VERS} -lroken
DPADD+=	${LIBCOM_ERR} ${LIBROKEN}

.endif

.include <bsd.prog.mk>
