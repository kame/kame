# /usr/home/ragini/Ripng/query/Makefile,v 1.1.1.1 1997/03/04 17:12:28 ragini Exp

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	rip6query
.if (${OPSYS} != NetBSD)
MAN8=	rip6query.8
.else
MAN=	rip6query.8
.endif
SRCS=	rip6query.c
CFLAGS+=	-I$(.CURDIR)/../include -DINET6
BINOWN=	root
BINMODE=	4555

.include <bsd.prog.mk>
