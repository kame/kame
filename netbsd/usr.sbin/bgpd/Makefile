PROG=	bgpd
SRCS=	main.c if.c rt_table.c task.c parse.c in6.c router.c \
	bgp.c bgp_input.c bgp_output.c bgp_util.c aspath.c \
	ripng.c ospf.c dump.c cfparse.y cftoken.l

MAN=	bgpd.conf.5 bgpd.8

CFLAGS+=-Wall
CPPFLAGS+=-DADVANCEDAPI -DINET6 -DUSE_RFC2292BIS -DHAVE_SEARCH_H=1 -I. \
	-DHAVE_STDARG_H -DYY_NO_UNPUT

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lcompat
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a ${LIBCOMPAT}
LDADD+=	-ly -ll
DPADD+=	${LIBY} ${LIBL}

.PATH:	${.CURDIR}/../../kame/bgpd

YFLAGS+=	-d

.include <bsd.prog.mk>
