PROG=	altqstat
SRCS=	altqstat.c qdisc_blue.c qdisc_cbq.c qdisc_cdnr.c qdisc_conf.c \
	qdisc_fifoq.c qdisc_hfsc.c qdisc_priq.o qdisc_red.c qdisc_rio.c \
	qdisc_wfq.c quip_client.c

MAN1=	altqstat.1

CFLAGS+=-DALTQ -DINET6 -I${.CURDIR}/../../kame/libaltq

LDADD+=	-lcurses
DPADD+=	${LIBCURSES}
LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/altqstat

.include <bsd.prog.mk>
