PROG=	bgpd
SRCS=	main.c if.c rt_table.c task.c parse.c in6.c router.c \
	bgp.c bgp_input.c bgp_output.c bgp_util.c aspath.c \
	ripng.c ospf.c dump.c cfparse.y cftoken.l
CLEANFILES+= lex.yy.c y.tab.h y.tab.c

MAN5=	bgpd.conf.5
MAN8=	bgpd.8

CFLAGS+=-I${.OBJDIR} -I${.CURDIR}/../../kame/bgpd
CFLAGS+=-DHAVE_STDARG_H -DADVANCEDAPI -DINET6 -DUSE_RFC2292BIS -DYY_NO_UNPUT
CFLAGS+=-DHAVE_GETIFADDRS

LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lcompat
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a ${LIBCOMPAT}
LDADD+=-ly -ll
DPADD+=	${LIBY} ${LIBL}

# FreeBSD special
SRCS+=y.tab.h

.PATH:	${.CURDIR}/../../kame/bgpd

.include <bsd.prog.mk>
