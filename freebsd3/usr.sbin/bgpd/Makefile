PROG=	bgpd
SRCS=	main.c if.c rt_table.c task.c parse.c in6.c router.c \
	bgp.c bgp_input.c bgp_output.c bgp_util.c aspath.c \
	ripng.c ospf.c dump.c cfparse.y cftoken.l
CLEANFILES+= lex.yy.c y.tab.h y.tab.c

MAN5=	bgpd.conf.5
MAN8=	bgpd.8

CFLAGS+=-I${.OBJDIR} -I${.CURDIR}/../../kame/bgpd
CFLAGS+= -DADVANCEDAPI -DADVANCEDAPI -DINET6 -DUSE_RFC2292BIS

LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6 -lcompat
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a ${LIBCOMPAT}
LDADD+=-ly -ll
DPADD+=	${LIBY} ${LIBL}

# FreeBSD special
SRCS+=y.tab.h

.PATH:	${.CURDIR}/../../kame/bgpd

.include <bsd.prog.mk>
