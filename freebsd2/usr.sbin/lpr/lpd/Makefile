#	@(#)Makefile	8.1 (Berkeley) 6/6/93

PROG=	lpd
CFLAGS+=-I${.CURDIR}/../common_source -DINET6
MAN8=	lpd.8
SRCS=	lpd.c printjob.c recvjob.c displayq.c rmjob.c startdaemon.c \
	lpdchar.c common.c modes.c
.PATH:	${.CURDIR}/../common_source

LDADD+=	-L${.CURDIR}/../../../lib/libinet6 \
	-L${.CURDIR}/../../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.include "../../Makefile.inc"
.include <bsd.prog.mk>
