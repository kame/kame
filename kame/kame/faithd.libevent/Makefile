# Copyright (c) 1996 WIDE Project. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted provided that the above copyright notice
# and this paragraph are duplicated in all such forms and that any
# documentation, advertising materials, and other materials related to
# such distribution and use acknowledge that the software was developed
# by the WIDE Project, Japan. The name of the Project may not be used to
# endorse or promote products derived from this software without
# specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS IS''
# AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
# LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE.

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	${PREFIX}/sbin
PROG=	faithd
SRCS=	faithd.c prefix.c tcp.c ftp.c

# libevent 0.4
SRCS+=	event.c select.c

.if (${OPSYS} != "NetBSD")
CFLAGS+= -I${.CURDIR}
CFLAGS+= -DHAVE_SELECT
.else
CPPFLAGS+= -I${.CURDIR} -DHAVE_SELECT
.endif
LDADD+=	-lutil
DPADD+=	${LIBUTIL}
.if (${OPSYS} != "NetBSD") && (${OPSYS} != "OpenBSD")
MAN8=	faithd.8
.else
MAN=	faithd.8
.endif

.include <bsd.prog.mk>
