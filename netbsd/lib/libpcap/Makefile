SRCDIR=	${.CURDIR}/../../kame/libpcap

LIB=	pcap
SRCS=	pcap-bpf.c pcap.c inet.c gencode.c optimize.c nametoaddr.c \
	etherent.c savefile.c bpf_filter.c bpf_image.c \
	scanner.c grammar.c version.c

MAN=	pcap.3

CFLAGS+=	-O2
DEFS=  -DHAVE_MALLOC_H=1 -DHAVE_SYS_IOCCOM_H=1 -DHAVE_SYS_SOCKIO_H=1 -DHAVE_ETHER_HOSTTON=1 -DHAVE_STRERROR=1 -DINET6=1 -DHAVE_SOCKADDR_SA_LEN=1 
CPPFLAGS+=	${DEFS} -I${SRCDIR} -I${.CURDIR} -I.
# workaround for gnuc.h and net/bpf.h
CPPFLAGS+=	-I${SRCDIR}/lbl -I${SRCDIR}/bpf
YFLAGS+=	-d

MKPIC=	no
# do not overwrite OS-suppplied lint database
NOLINT=	yes

scanner.o:	scanner.c tokdefs.h
tokdefs.h:	grammar.c

grammar.c: grammar.y
	@rm -f grammar.c tokdefs.h
	$(YACC) $(YFLAGS) $<
	mv y.tab.c grammar.c
	mv y.tab.h tokdefs.h

grammar.o: grammar.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Dyylval=pcap_lval -c grammar.c
grammar.po: grammar.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Dyylval=pcap_lval -c -pg -o $@ grammar.c

version.c: VERSION
	@rm -f $@
	sed -e 's/.*/char pcap_version[] = "&";/' $> > $@

.PATH:	${SRCDIR} ${SRCDIR}/bpf/net

.include <bsd.lib.mk>

CLEANFILES+=	version.c grammar.c tokdefs.h scanner.c
