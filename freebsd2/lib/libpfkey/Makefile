SRCDIR=	${.CURDIR}/../../kame/libipsec

LIB=	pfkey
CFLAGS+=-g
CFLAGS+=-DIPSEC_DEBUG -DIPSEC -DINET6 -I. -DYY_NO_UNPUT

.PATH:	${SRCDIR} ${.CURDIR}/../../sys/netkey
SRCS=	pfkey.c pfkey_dump.c ipsec_strerror.c
SRCS+=	key_debug.c
#YPREFIX=__libyy
#LPREFIX=__libyy
#YHEADER=1

#MAN=	ipsec_set_policy.3 ipsec_strerror.3
#MLINKS+=ipsec_set_policy.3 ipsec_get_policylen.3 \
#	ipsec_set_policy.3 ipsec_dump_policy.3

MKPIC=no
NOPROFILE=no
MKLINT=no

install::

.include <bsd.lib.mk>
