SRCDIR=	${.CURDIR}/../../kame/libpcap

LIB=	pcap
SRCS=	pcap-bpf.c pcap.c inet.c gencode.c optimize.c nametoaddr.c \
	etherent.c savefile.c bpf_filter.c bpf_image.c \
	scanner.c grammar.c version.c

MAN3=	pcap.3

CFLAGS+=	-O2
DEFS =  -DHAVE_SYS_IOCCOM_H=1 -DHAVE_SYS_SOCKIO_H=1 -DHAVE_ETHER_HOSTTON=1 -DHAVE_STRERROR=1 -DINET6=1 -DHAVE_SOCKADDR_SA_LEN=1 
CFLAGS+=	${DEFS} -I${SRCDIR} -I${.OBJDIR}
# workaround for gnuc.h and net/bpf.h
CFLAGS+=	-I${SRCDIR}/lbl -I${SRCDIR}/bpf
YFLAGS+=	-d

#
# Flex and bison allow you to specify the prefixes of the global symbols
# used by the generated parser.  This allows programs to use lex/yacc
# and link against libpcap.  If you don't have flex or bison, get them.
#
LEX = flex -Ppcap_
YACC = bison -y -p pcap_

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
	$(CC) $(CFLAGS) $(CPPFLAGS) -Dyylval=pcap_lval -c $>
grammar.po: grammar.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -Dyylval=pcap_lval -c -pg -o $@ $>

version.c: VERSION
	@rm -f $@
	sed -e 's/.*/char pcap_version[] = "&";/' $> > $@

.PATH:	${SRCDIR} ${SRCDIR}/bpf/net

.include <bsd.lib.mk>

CLEANFILES+=	version.c grammar.c tokdefs.h scanner.c
