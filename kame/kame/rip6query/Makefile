#	$NetBSD: Makefile,v 1.7 1995/03/18 14:56:21 cgd Exp $
#	@(#)Makefile	8.1 (Berkeley) 6/5/93

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	rip6query
.if (${OPSYS} != "NetBSD")
MAN8=	rip6query.8
.else
MAN=	rip6query.8
.endif

.if (${OPSYS} == NetBSD)
CPPFLAGS+=	-DINET6 -I${.CURDIR}/../route6d
.else
CFLAGS+=	-DINET6 -I${.CURDIR}/../route6d
.endif
LDADD+=	-L${.OBJDIR}/../libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
