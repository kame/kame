SRCDIR=	${.CURDIR}/../../kame/prefix

PROG=	prefix
MAN8=	prefix.8

realinstall:
	install $(COPY) -o $(BINOWN) -g $(BINGRP) -m 555 $(SRCDIR)/prefix.sh \
		${DESTDIR}${BINDIR}/prefix

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
