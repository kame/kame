PROG=	faithd
SRCS=	faithd.c tcp.c ftp.c rsh.c

MAN=	faithd.8

#CPPFLAGS+= -DFAITH4

LDADD+=	-lutil
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L${.OBJDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	${.OBJDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/faithd

.include <bsd.prog.mk>
