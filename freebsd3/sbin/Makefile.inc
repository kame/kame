BINDIR?=/usr/local/v6/sbin
MANDIR=	/usr/local/v6/man/man
NOSHARED=	yes
.if defined(USE_LIBBIND6) && ${USE_LIBBIND6} == YES
LDADD+=-L/usr/local/lib -lbind
DPADD+=/usr/local/lib/libbind.a
.endif
