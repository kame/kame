#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: src/usr.bin/tftp/Makefile,v 1.5 2002/02/08 23:07:35 markm Exp $

PROG=	tftp
SRCS=	main.c tftp.c tftpsubs.c
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

DPADD=	${LIBEDIT} ${LIBTERMCAP}
LDADD=	-ledit -ltermcap

.include <bsd.prog.mk>
