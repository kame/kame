#	@(#)Makefile	8.1 (Berkeley) 6/5/93
#	$Id: Makefile,v 1.7 1998/09/19 22:42:02 obrien Exp $

PROG=	ping
MAN8=	ping.8
BINMODE=4555
COPTS+=	-Wall -Wmissing-prototypes -DIPSEC
.if ${MACHINE_ARCH} == "alpha"
COPTS+= -fno-builtin	# GCC's builtin memcpy doesn't do unaligned copies
.endif
DPADD=	${LIBM}
LDADD=	-lm
LDADD+= -L${.OBJDIR}/../../lib/libipsec \
	-L${.OBJDIR}/../../lib/libipsec/obj \
	-L/usr/local/v6/lib -lipsec
DPADD+= ${.OBJDIR}/../../lib/libipsec/libipsec.a \
	${.OBJDIR}/../../lib/libipsec/obj/libipsec.a \
	/usr/local/v6/lib/libipsec.a
LDADD+= -L${.OBJDIR}/../../lib/libinet6 \
	-L${.OBJDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.OBJDIR}/../../lib/libinet6/libinet6.a \
	${.OBJDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
