#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: src/sbin/ping/Makefile,v 1.7.2.1 1999/08/29 15:15:06 peter Exp $

PROG=	ping
MAN8=	ping.8
BINMODE=4555
COPTS+=	-Wall -Wmissing-prototypes -DIPSEC
.if ${MACHINE_ARCH} == "alpha"
COPTS+= -fno-builtin	# GCC's builtin memcpy doesn't do unaligned copies
.endif
DPADD=	${LIBM}
LDADD=	-lm
LDADD+= -L${.OBJDIR}/../../lib/libipsec -L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -lipsec -linet6
DPADD+= ${.OBJDIR}/../../lib/libipsec/libipsec.a \
	/usr/local/v6/lib/libipsec.a
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
