PROG=	racoon
SRCS=	main.c session.c isakmp.c handler.c \
	isakmp_ident.c isakmp_agg.c isakmp_base.c \
	isakmp_quick.c isakmp_inf.c isakmp_newg.c \
	pfkey.c admin.c ipsec_doi.c oakley.c grabmyaddr.c \
	policy.c localconf.c remoteconf.c crypto_openssl.c algorithm.c \
	cfparse.c cftoken.c strnames.c \
	vmbuf.c plog.c logger.c schedule.c str2val.c misc.c sockmisc.c \
	proposal.c sainfo.c vendorid.c safefile.c backupsa.c \
	dnssec.c getcertsbyname.c

SRCS+=	rijndael-alg-fst.c rijndael-api-fst.c sha2.c
CFLAGS+=-I${SRCDIR}/missing -DHAVE_ARC4RANDOM=1

# debugging code with print-isakmp.c
#SRCS+=	print-isakmp.c
#CFLAGS+=-I${SRCDIR}/../tcpdump -I${SRCDIR}/../tcpdump/lbl \
#	-DHAVE_PRINT_ISAKMP_C=1

# for debugging malloc/mfree
#.if exists(/usr/local/lib/libefence.a) || exists(/usr/local/lib/libefence.so)
#LDADD+=-L/usr/local/lib -lefence
#.endif

MAN5=	racoon.conf.5
MAN8=	racoon.8

.include <bsd.prog.mk>

CLEANFILES+=	y.tab.h cfparse.c cftoken.c
.PATH: ${SRCDIR}/missing/crypto/rijndael ${SRCDIR}/missing/crypto/sha2
