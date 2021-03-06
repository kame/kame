#	$NetBSD: Makefile,v 1.4 2000/12/12 22:41:51 itojun Exp $

.include <bsd.own.mk>

PROG=	racoon
SRCS=	main.c session.c isakmp.c handler.c arc4random.c \
	isakmp_ident.c isakmp_agg.c isakmp_base.c \
	isakmp_quick.c isakmp_inf.c isakmp_newg.c \
	gssapi.c \
	pfkey.c admin.c ipsec_doi.c oakley.c grabmyaddr.c \
	policy.c localconf.c remoteconf.c crypto_openssl.c algorithm.c \
	cfparse.c cftoken.c strnames.c \
	vmbuf.c plog.c logger.c schedule.c str2val.c misc.c sockmisc.c \
	proposal.c sainfo.c vendorid.c safefile.c backupsa.c \
	dnssec.c getcertsbyname.c
SRCS+=	rijndael-alg-fst.c rijndael-api-fst.c

MAN=	racoon.8 racoon.conf.5

# debugging code with print-isakmp.c
#SRCS+=	print-isakmp.c
#CPPFLAGS+=-I${TCPDUMPSRCDIR} -I${TCPDUMPSRCDIR}/lbl -DHAVE_PRINT_ISAKMP_C=1

# kerberos
.if (${MKKERBEROS} != "no")
CPPFLAGS+=-I${DESTDIR}/usr/include/krb5
.endif

# for debugging malloc/free
#.if exists(/usr/pkg/lib/libefence.a) || exists(/usr/pkg/lib/libefence.so)
#LDADD+=-L/usr/pkg/lib -lefence
#.endif

LIBPFKEYDIR!=	cd ${.CURDIR}/../libpfkey; ${MAKE} print-objdir
LDADD+=	-L${LIBPFKEYDIR} -lpfkey
DPADD+=	${LIBPFKEYDIR}/libpfkey.a
.if (${MKKERBEROS} != "no")
LDADD+=	-lgssapi -lkrb5 -lcom_err -lroken -lasn1
DPADD+=	${LIBGSSAPI} ${LIBKRB5} ${LIBCOM_ERR} ${LIBROKEN} ${LIBASN1}
.endif
LDADD+=	-lipsec -ly -ll -lcrypto
DPADD+=	${LIBIPSEC} ${LIBY} ${LIBL} ${LIBCRYPTO}

#CFLAGS+=-g
OPTFLAG+=-DHAVE_PFKEYV2 -DYIPS_DEBUG
CPPFLAGS+=-DINET6 -DHAVE_FUNCTION_MACRO=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBL=1 -DHAVE_LIBY=1 -DENABLE_IPV6=1 -DADVAPI=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_LIMITS_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_VARARGS_H=1 -DTIME_WITH_SYS_TIME=1 -DRETSIGTYPE=void -DHAVE_VPRINTF=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 -DHAVE_STRERROR=1 -DHAVE_STRTOL=1 -DHAVE_STRTOUL=1 -DHAVE_STRDUP=1  $(OPTFLAG) -DIPSEC -I${RACOONSRCDIR} -I. -DSYSCONFDIR=\"$(ETCDIR)\"
CPPFLAGS+=-DHAVE_OPENSSL_OPENSSLV_H=1
CPPFLAGS+=-DYY_NO_UNPUT
CPPFLAGS+=-DHAVE_GETRRSETBYNAME
CPPFLAGS+=-I${LIBPFKEYSRCDIR}
CPPFLAGS+=-I${RACOONSRCDIR}/missing
.if (${MKKERBEROS} != "no")
CPPFLAGS+=-DHAVE_GSSAPI 
.endif
YFLAGS+=-d

# Certificate support
CPPFLAGS+=-DHAVE_SIGNING_C=1 -DHAVE_OPENSSL_PEM_H=1 -DHAVE_OPENSSL_X509_H=1 \
	-DHAVE_OPENSSL_EVP_H=1
#	-DHAVE_OPENSSL_RC5_H=1 -DHAVE_OPENSSL_IDEA_H=1 
CLEANFILES+=	cfparse.c cftoken.c cfparse.h

.include <bsd.prog.mk>

.PATH:	${RACOONSRCDIR} ${TCPDUMPSRCDIR} ${RACOONSRCDIR}/missing/crypto/rijndael ${RACOONSRCDIR}/missing/crypto/sha2 ${RACOONSRCDIR}/missing
