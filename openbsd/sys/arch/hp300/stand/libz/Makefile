#	$OpenBSD: Makefile,v 1.1 1997/07/14 08:14:51 downsj Exp $

LIB=	z

.PATH:  ${.CURDIR}/../../../../lib/libz

CFLAGS= -O2 -msoft-float -D_ZLIB_PRIVATE -I${.CURDIR}/../../../../lib/libz

SRCS=	adler32.c crc32.c infblock.c infcodes.c inffast.c \
	inflate.c inftrees.c infutil.c

${OBJS}:	${.CURDIR}/../Makefile.inc

install:

NOPIC=
NOPROFILE=

.include <bsd.lib.mk>
