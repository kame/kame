#	@(#)Makefile	8.1 (Berkeley) 6/4/93
#	$Id: Makefile,v 1.5.2.1 1999/05/02 09:36:16 brian Exp $

PROG=	tftpd
SRCS=	tftpd.c tftpsubs.c
DPADD=	${LIBUTIL}
LDADD=	-lutil
MAN8=	tftpd.8
CFLAGS+=-I${.CURDIR}/../../usr.bin/tftp
.PATH:	${.CURDIR}/../../usr.bin/tftp

CFLAGS+=-DINET6
LDADD+=	-L${.OBJDIR}/../../../src/libinet6 \
	-L${.OBJDIR}/../../../src/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../../src/libinet6/libinet6.a \
	${.OBJDIR}/../../../src/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include <bsd.prog.mk>
