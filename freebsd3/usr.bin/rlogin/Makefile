#	@(#)Makefile	8.1 (Berkeley) 7/19/93
#	$Id: Makefile,v 1.13 1998/10/09 06:45:28 markm Exp $

PROG=	rlogin
SRCS=	rlogin.c
CFLAGS+=-Wall

BINMODE=4555
INSTALLFLAGS=-fschg

LDADD+= -L${.OBJDIR}/../../lib/libinet6 \
        -L${.OBJDIR}/../../lib/libinet6/obj \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
        ${.OBJDIR}/../../lib/libinet6/obj/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.if exists(${DESTDIR}${LIBDIR}/libkrb.a) && defined(MAKE_KERBEROS4)
SRCS+=	krcmd.c kcmd.c rcmd_util.c encrypt.c
DPADD+=	${LIBUTIL} ${LIBKRB} ${LIBDES} ${LIBCRYPT}
CFLAGS+=-DKERBEROS -DCRYPT -DHAVE_CONFIG_H \
	-I${.CURDIR}/../../kerberosIV/include \
	-I${.CURDIR}/../../crypto/kerberosIV/include \
	-I${.CURDIR}/../../crypto/kerberosIV/lib/roken \
	-I${.CURDIR}/../../crypto/kerberosIV/appl/bsd
LDADD+=	-lutil -lkrb -ldes -lcrypt
DISTRIBUTION=	krb
.PATH:	${.CURDIR}/../../crypto/kerberosIV/appl/bsd
.endif

.include <bsd.prog.mk>
