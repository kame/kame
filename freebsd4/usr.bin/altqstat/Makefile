PROG=	altqstat
SRCS=	altqstat.c qdisc_blue.c qdisc_cbq.c qdisc_cdnr.c qdisc_conf.c \
	qdisc_fifoq.c qdisc_hfsc.c qdisc_priq.o qdisc_red.c qdisc_rio.c \
	qdisc_wfq.c quip_client.c

MAN1=	altqstat.1

CFLAGS+=-DALTQ -DINET6 -Wall -I${.CURDIR}/../../kame/libaltq

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

LDADD+=	-lcurses
DPADD+=	${LIBCURSES}

.PATH:	${.CURDIR}/../../kame/altqstat

.include <bsd.prog.mk>
