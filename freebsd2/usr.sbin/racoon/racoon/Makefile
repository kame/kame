PROG=	racoon
SRCS=	handler.c isakmp.c isakmp_inf.c ipsec_doi.c pfkey.c main.c \
	post_com.c schedule.c session.c crypto.c cfparse.c cftoken.c \
	admin.c misc.c vmbuf.c
#SRCS+=	signing.c

# debugging code with print-isakmp.c
SRCS+=	print-isakmp.c
CFLAGS+=-I${SRCDIR}/../tcpdump -I${SRCDIR}/../tcpdump/lbl \
	-DHAVE_PRINT_ISAKMP_C=1 -DSSLVERSION=${SSLVERNUM}

MAN5=	racoon.conf.5
MAN8=	racoon.8

.include <bsd.prog.mk>

CLEANFILES+=	y.tab.h cfparse.c cftoken.c
