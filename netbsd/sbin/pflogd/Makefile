#	$OpenBSD: Makefile,v 1.4 2003/03/01 06:11:20 cloder Exp $

CFLAGS+=-Wall -Werror -Wmissing-prototypes -Wshadow
LDADD+= -lpcap -lutil
DPAPP+=	${LIBPCAP} ${LIBUTIL}

PROG=	pflogd
SRCS=	pflogd.c
MAN=	pflogd.8

CPPFLAGS=	-I${.CURDIR}/../../../kame/kame/libpcap

.PATH: ${.CURDIR}/../../../kame/kame/pflogd

.include <bsd.prog.mk>
