#	$NetBSD: Makefile,v 1.5 1998/03/05 14:02:00 christos Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	sysctl
MAN=	sysctl.8

CPPFLAGS+=-DINET6 -DIPSEC
LDFLAGS+= -static
#CFLAGS+=-DTCP6

.include <bsd.prog.mk>
