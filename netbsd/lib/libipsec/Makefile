SRCDIR=	${.CURDIR}/../../kame/libipsec

LIB=	ipsec
CFLAGS+=-g
CPPFLAGS+=-DIPSEC_DEBUG -DIPSEC -DINET6 -I.

.PATH:	${SRCDIR} ${.CURDIR}/../../sys/netkey
SRCS=	pfkey.c pfkey_dump.c
SRCS+=	ipsec_get_policylen.c ipsec_strerror.c key_debug.c
SRCS+=	policy_parse.y policy_token.l
YFLAGS+=	-d -p __libyy
LFLAGS+=	-P__libyy

MAN=	ipsec_set_policy.3 ipsec_strerror.3
MLINKS+=ipsec_set_policy.3 ipsec_get_policylen.3 \
	ipsec_set_policy.3 ipsec_dump_policy.3

CLEANFILES+=	y.tab.h

# Lex
.l:
	${LEX.l} ${.IMPSRC}
	${LINK.c} -o ${.TARGET} lex.__libyy.c ${LDLIBS} -ll
	rm -f lex.__libyy.c
.l.c:
	${LEX.l} ${.IMPSRC}
	mv lex.__libyy.c ${.TARGET}
.l.o:
	${LEX.l} ${.IMPSRC}
	${COMPILE.c} -o ${.TARGET} lex.__libyy.c 
	rm -f lex.__libyy.c

MKPIC=no

.include <bsd.lib.mk>
