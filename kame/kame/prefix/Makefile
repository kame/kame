#	From: @(#)Makefile	8.1 (Berkeley) 6/5/93
#	$Id: Makefile,v 1.1 1999/08/08 23:31:13 itojun Exp $

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	$(PREFIX)/sbin
PROG=	prefix
SRCS=	prefix.c
.if (${OPSYS} != "NetBSD")
MAN8=	prefix.8
.else
MAN=	prefix.8
.endif

CFLAGS+=-g
.if (${OPSYS} != "NetBSD")
CFLAGS+=-DINET6
.else
CPPFLAGS+=-DINET6
.endif
LDADD+=	-L${.OBJDIR}/../libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
