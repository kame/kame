#	$OpenBSD: Makefile,v 1.14 2002/02/17 07:52:38 hugh Exp $

PROG=	systat

.PATH:	${.CURDIR}/../../usr.bin/vmstat

CPPFLAGS+=-I${.CURDIR}/../../usr.bin/vmstat
SRCS=	cmds.c cmdtab.c disks.c dkstats.c fetch.c iostat.c keyboard.c \
	main.c mbufs.c netcmds.c netstat.c pigs.c swap.c vmstat.c
DPADD=	${LIBCURSES} ${LIBM} ${LIBKVM}
LDADD=	-lcurses -lm -lkvm
BINGRP=	kmem
BINMODE=2555

CPPFLAGS+=-DINET6

LDADD+= -L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.if (${MACHINE_ARCH} == "vax")
cmds.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -O0 -c $<
.endif

.include <bsd.prog.mk>

