PROG=	altqstat
SRCS=	altqstat.c qdisc_blue.c qdisc_cbq.c qdisc_cdnr.c qdisc_conf.c \
	qdisc_fifoq.c qdisc_hfsc.c qdisc_red.c qdisc_rio.c qdisc_wfq.c \
	quip_client.c

MAN1=	altqstat.1

CFLAGS+=-DALTQ -DINET6 -I${.CURDIR}/../../kame/libaltq

LDADD+=	-lcurses
DPADD+=	${LIBCURSES}

.PATH:	${.CURDIR}/../../kame/altqstat

.include <bsd.prog.mk>
