SRCDIR=	${.CURDIR}/../../kame/libipsec

LIB=	ipsec
CFLAGS+=-g -I.
CFLAGS+=-DIPSEC_DEBUG -DIPSEC -DINET6

.PATH:	${SRCDIR} ${.CURDIR}/../../sys/netkey
SRCS=	pfkey.c pfkey_dump.c
SRCS+=	ipsec_strerror.c policy_parse.y policy_token.l
SRCS+=	ipsec_dump_policy.c ipsec_get_policylen.c
SRCS+=	key_debug.c
LDADD+=	-ll -ly
CLEANFILES+=	y.tab.c y.tab.h
YFLAGS+=-d -p __libyy
LFLAGS+=-P__libyy

MAN3=	ipsec_set_policy.3 ipsec_strerror.3
MLINKS+=ipsec_set_policy.3 ipsec_get_policylen.3 \
	ipsec_set_policy.3 ipsec_dump_policy.3

.include <bsd.lib.mk>
