#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: src/usr.sbin/inetd/Makefile,v 1.5.2.8 2000/02/01 09:21:22 des Exp $

PROG=	inet46d
SRCS=	inetd.c builtins.c
MAN8=	inetd.8
MLINKS= inetd.8 inetd.conf.5 \
	inetd.8 inet46d.8 \
	inetd.8 inetd46d.conf.5
COPTS+=	-Wall -DLOGIN_CAP -DLIBWRAP
COPTS+=	-DIPSEC

COPTS+=	-Wall -DLOGIN_CAP
#COPTS+=	-DSANITY_CHECK

DPADD+=	${LIBUTIL} ${LIBWRAP}
LDADD+=	-lutil -lwrap
LDADD+=	-L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+=	${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
        /usr/local/v6/lib/libinet6.a
CFLAGS+=	-DINET6 -DIPSEC

.include <bsd.prog.mk>
