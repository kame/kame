PROG=	racoon
SRCS=	main.c session.c isakmp.c handler.c random.c \
	isakmp_ident.c isakmp_agg.c isakmp_base.c \
	isakmp_quick.c isakmp_inf.c isakmp_newg.c \
	pfkey.c admin.c ipsec_doi.c oakley.c grabmyaddr.c \
	policy.c localconf.c remoteconf.c crypto_openssl.c algorithm.c \
	cfparse.c cftoken.c strnames.c \
	vmbuf.c plog.c logger.c schedule.c str2val.c misc.c sockmisc.c \
	proposal.c sainfo.c vendorid.c safefile.c backupsa.c \
	dnssec.c getcertsbyname.c

# debugging code with print-isakmp.c
SRCS+=	print-isakmp.c
SRCS+=	rijndael-alg-fst.c rijndael-api-fst.c
CFLAGS+=-I${SRCDIR}/../tcpdump -I${SRCDIR}/../tcpdump/lbl \
	-DHAVE_PRINT_ISAKMP_C=1
CFLAGS+=-I${SRCDIR}/missing

MAN5=	racoon.conf.5
MAN8=	racoon.8

y.tab.h:	cfparse.o
cftoken.o:	y.tab.h cftoken.l

.include <bsd.prog.mk>

CLEANFILES+=	y.tab.h cfparse.c cftoken.c
.PATH: ${SRCDIR}/missing/crypto/rijndael
