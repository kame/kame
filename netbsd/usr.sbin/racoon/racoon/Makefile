PROG=	racoon
SRCS=	main.c session.c isakmp.c handler.c \
	isakmp_ident.c isakmp_agg.c \
	isakmp_quick.c isakmp_inf.c isakmp_newg.c \
	pfkey.c admin.c ipsec_doi.c oakley.c grabmyaddr.c signing.c \
	policy.c localconf.c remoteconf.c crypto_openssl.c algorithm.c \
	cfparse.c cftoken.c strnames.c \
	vmbuf.c plog.c logger.c schedule.c str2val.c misc.c sockmisc.c

# debugging code with print-isakmp.c
SRCS+=	print-isakmp.c
CPPFLAGS+=-I${SRCDIR}/../tcpdump -I${SRCDIR}/../tcpdump/lbl \
	-DHAVE_PRINT_ISAKMP_C=1 

# for debugging malloc/free
#.if exists(/usr/pkg/lib/libefence.a) || exists(/usr/pkg/lib/libefence.so)
#LDADD+=-L/usr/pkg/lib -lefence
#.endif

MAN=	racoon.8 racoon.conf.5

.include <bsd.prog.mk>

CLEANFILES+=	y.tab.h cfparse.c cftoken.c
