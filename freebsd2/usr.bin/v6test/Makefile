SRCDIR=	${.CURDIR}/../../kame/v6test

PROG=	v6test
SRCS=	v6test.c cksum.c testcap.c getconfig.c

CFLAGS+=-I${SRCDIR} -DIPSEC
CFLAGS+=-Duint8_t=u_int8_t -Duint16_t=u_int16_t -Duint32_t=u_int32_t
CFLAGS+=-I${.CURDIR}/../../kame/libpcap -DHAVE_PCAP
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L${.CURDIR}/../../lib/libpcap \
	-L/usr/local/v6/lib -linet6 -lpcap
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a \
	${.CURDIR}/../../lib/libpcap/libcap.a \
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
