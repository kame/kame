SRCDIR=	${.CURDIR}/../../kame/v6test

PROG=	v6test
SRCS=	v6test.c cksum.c testcap.c getconfig.c
MAN=	v6test.1

CFLAGS+=-I${SRCDIR}
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../lib/libinet6/libinet6.a \
	${.CURDIR}/../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

#CFLAGS += -DDEFAUT_IF="ep0"
CONFS = ext.conf ndp.conf synloop.conf
PREFIX?= /usr/local/v6
CONFDIR= $(PREFIX)/share/v6test

.PATH:	${SRCDIR}

.include <bsd.prog.mk>

afterinstall:
	[ -d $(CONFDIR) ] || mkdir -p $(CONFDIR); \
	for i in $(CONFS); do \
		cp $(SRCDIR)/conf/$$i $(CONFDIR); \
	done
