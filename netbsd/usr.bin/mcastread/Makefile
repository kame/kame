SRCDIR=	${.CURDIR}/../../kame/mcastread

PROG=	mcastread

CPPFLAGS+=-DINET6
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 -L${.OBJDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	${.OBJDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN=	mcastread.1

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
