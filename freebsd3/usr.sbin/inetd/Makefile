#	@(#)Makefile	8.1 (Berkeley) 6/6/93
#	$Id: Makefile,v 1.5.2.2 1999/05/07 06:50:28 markm Exp $

PROG=	inetd
MAN8=	inetd.8
MLINKS=	inetd.8 inetd.conf.5
COPTS+=	-Wall -DLOGIN_CAP -DLIBWRAP
COPTS+=	-DIPSEC
#COPTS+=	-DSANITY_CHECK

DPADD+=	${LIBUTIL} ${LIBWRAP}
LDADD+=	-lutil -lwrap
LDADD+=	-L${.OBJDIR}/../../lib/libipsec \
	-L${.OBJDIR}/../../lib/libipsec/obj \
	-L/usr/local/v6/lib -lipsec
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	${.OBJDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+= -L${.OBJDIR}/../../lib/libinet6 \
        -L${.OBJDIR}/../../lib/libinet6/obj \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
        ${.OBJDIR}/../../lib/libinet6/obj/libinet6.a \
        /usr/local/v6/lib/libinet6.a
CFLAGS+=	-DINET6 -DIPSEC

.include <bsd.prog.mk>
