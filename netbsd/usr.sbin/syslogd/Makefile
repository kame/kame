#	$NetBSD: Makefile,v 1.13 1999/03/19 00:43:03 perry Exp $
#	from: @(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	syslogd
MAN=	syslogd.8 syslog.conf.5
DPADD+=${LIBUTIL}
LDADD+=-lutil
#make symlink to old socket location for transitional period
SYMLINKS=	/var/run/log /dev/log

CPPFLAGS+=-DINET6
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

# KAME scopeid hack
CPPFLAGS+=-DKAME_SCOPEID

.include <bsd.prog.mk>
