.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	${PREFIX}/sbin
PROG=	mip6config
SRCS=	mip6config.c utils.c

.if (${OPSYS} != "NetBSD")
CFLAGS+=-DINET6
.else
CPPFLAGS+=-DINET6
.endif
CFLAGS+=-Wall
LDADD+=	-L${.OBJDIR}/../libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.if (${OPSYS} != "NetBSD")
MAN1=	mip6config.8
.else
MAN=	mip6config.8
.endif

.include <bsd.prog.mk>
