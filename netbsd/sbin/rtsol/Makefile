SRCDIR=	${.CURDIR}/../../kame/rtsold

PROG=	rtsol
SRCS=	rtsold.c rtsol.c if.c probe.c

CPPFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
LDADD+=	-lkvm
DPADD+=	${LIBKVM}

#MAN=	rtsold.8
NOMAN=	yes

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
