PREFIX=	/usr/local/v6
BINDIR?= $(PREFIX)/bin
LIBDIR= $(PREFIX)/lib
.if (${OPSYS} != NetBSD)
MANDIR=	$(PREFIX)/man/man
.else
MANDIR=	$(PREFIX)/man
.endif
