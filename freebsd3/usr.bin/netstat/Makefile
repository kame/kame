#	@(#)Makefile	8.1 (Berkeley) 6/12/93

PROG=	netstat
SRCS=	if.c inet.c inet6.c main.c mbuf.c mroute.c ipx.c route.c \
	unix.c atalk.c mroute6.c # iso.c ns.c tp_astring.c

CFLAGS+=-g
#.PATH:	${.CURDIR}/../../sys/netiso
BINGRP=	kmem
BINMODE=2555
DPADD=	${LIBKVM} ${LIBIPX}
LDADD=	-lkvm -lipx
CFLAGS+=	-DINET6 -DIPSEC
LDADD+= -L${.OBJDIR}/../../lib/libinet6 \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
