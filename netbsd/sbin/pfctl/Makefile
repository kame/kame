#	$OpenBSD: Makefile,v 1.12 2003/01/09 17:33:19 henning Exp $

PROG=	pfctl
SRCS=	pfctl.c parse.y pfctl_parser.c pf_print_state.c pfctl_altq.c pfctl_osfp.c
SRCS+=	pfctl_radix.c pfctl_table.c pfctl_qstats.c
#CFLAGS+= -Wall -Wmissing-prototypes -Wno-uninitialized
#CFLAGS+= -Wstrict-prototypes
YFLAGS=
MAN=	pfctl.8

LDADD+=	-lm
DPADD+=	${LIBM}

SRCS+=	arc4random.c

.PATH: ${.CURDIR}/../../../kame/kame/pfctl ${.CURDIR}/../../../kame/kame/libinet6

.include <bsd.prog.mk>
