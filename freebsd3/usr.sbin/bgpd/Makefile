PROG=	bgpd
SRCS=	main.c if.c rt_table.c task.c parse.c in6.c router.c \
	bgp.c bgp_input.c bgp_output.c bgp_util.c aspath.c \
	ripng.c ospf.c dump.c

MAN5=	bgpd.conf.5
MAN8=	bgpd.8

CFLAGS+=	-Wall
CFLAGS+=	-DADVANCEDAPI -DINET6

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6 -lcompat
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a ${LIBCOMPAT}

.PATH:	${.CURDIR}/../../kame/bgpd

.include <bsd.prog.mk>
