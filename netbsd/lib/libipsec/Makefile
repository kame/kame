SRCDIR=	${.CURDIR}/../../kame/libipsec

LIB=	ipsec
CFLAGS+=-g
CPPFLAGS+=-DIPSEC_DEBUG -DIPSEC -DINET6 -I.

.PATH:	${SRCDIR} ${.CURDIR}/../../sys/netkey
SRCS=	pfkey.c pfkey_dump.c
SRCS+=	ipsec_strerror.c policy_parse.y policy_token.l
SRCS+=	ipsec_get_policylen.c ipsec_dump_policy.c
SRCS+=	key_debug.c
YFLAGS+=	-d -p __libyy
LFLAGS+=	-P__libyy
LFLAGS+=	-olex.yy.c

MAN=	ipsec_set_policy.3 ipsec_strerror.3
MLINKS+=ipsec_set_policy.3 ipsec_get_policylen.3 \
	ipsec_set_policy.3 ipsec_dump_policy.3

CLEANFILES+=	y.tab.h

MKPIC=no

.include <bsd.lib.mk>
