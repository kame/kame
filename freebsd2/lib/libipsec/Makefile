LIB=	ipsec
CFLAGS+=-g
CFLAGS+=-DIPSEC_DEBUG -DIPSEC -DINET6

.PATH:	${.CURDIR}/../../sys/netkey
SRCS=	pfkey.c pfkey_dump.c
SRCS+=	ipsec_policy.c ipsec_strerror.c key_debug.c

MAN3=	ipsec_set_policy.3 ipsec_strerror.3
MLINKS+=ipsec_set_policy.3 ipsec_get_policylen.3 \
	ipsec_set_policy.3 ipsec_dump_policy.3

.include <bsd.lib.mk>
