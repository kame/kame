#	From: @(#)Makefile	8.1 (Berkeley) 6/6/93
#	$Id: Makefile,v 1.6 1998/09/11 18:49:33 wollman Exp $

PROG=	pac
CFLAGS+=-I${.CURDIR}/../common_source -DINET6 ${CWARNFLAGS}
MAN8=	pac.8
.PATH:	${.CURDIR}/../common_source
DPADD=	${LIBLPR}
LDADD=	${LIBLPR}
LDADD+= -L${.OBJDIR}/../../../lib/libinet6 \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../../lib/libinet6/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
