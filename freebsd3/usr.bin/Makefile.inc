BINDIR?=	/usr/local/v6/bin
MANDIR=	/usr/local/v6/man/man
.if defined(USE_LIBBIND6) && ${USE_LIBBIND6} == YES
LDADD+=-L/usr/local/lib -lbind
DPADD+=/usr/local/lib/libbind.a
.endif
