SRCDIR=	${.CURDIR}/../../kame/v6test

PROG=	v6test
SRCS=	v6test.c cksum.c testcap.c getconfig.c

CFLAGS+=-I${SRCDIR} -DIPSEC
CFLAGS+=-I${.OBJDIR}/../../kame/libpcap -DHAVE_LIBPCAP
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6 \
	-L${.OBJDIR}/../../lib/libpcap \
	-L/usr/local/v6/lib -lpcap -linet6
DPADD+= ${.OBJDIR}/../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a \
	${.OBJDIR}/../../lib/libpcap/libcap.a \
	/usr/local/v6/lib/libpcap.a

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
