#	@(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	tftp
SRCS=	main.c tftp.c tftpsubs.c

CFLAGS+=-DINET6
LDADD+= -L${.OBJDIR}/../../lib/libinet6 \
        -L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
        /usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
