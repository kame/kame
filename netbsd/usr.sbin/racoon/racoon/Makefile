PROG=	racoon
SRCS=	handler.c isakmp.c isakmp_inf.c ipsec_doi.c pfkey.c main.c \
	post_com.c schedule.c session.c crypto.c cfparse.c cftoken.c \
	admin.c misc.c vmbuf.c

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
