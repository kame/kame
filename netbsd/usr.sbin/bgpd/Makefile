PROG=	bgpd
SRCS=	main.c if.c rt_table.c task.c parse.c in6.c router.c \
	bgp.c bgp_input.c bgp_output.c bgp_util.c aspath.c \
	ripng.c ospf.c dump.c

MAN=	bgpd.conf.5 bgpd.8

CFLAGS+=	-Wall
CPPFLAGS+=	-DADVANCEDAPI -DINET6   -DHAVE_SEARCH_H=1 

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lcompat
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a ${LIBCOMPAT}

.PATH:	${.CURDIR}/../../kame/bgpd

.include <bsd.prog.mk>
