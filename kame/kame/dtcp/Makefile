.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	$(PREFIX)/sbin

.if (${OPSYS} != "NetBSD")
MAN8=	dtcps.8 dtcpc.8
.else
MAN=	dtcps.8 dtcpc.8
.endif

.if (${OPSYS} == "NetBSD")
LPREFIX=	/usr/pkg/bin
.else
LPREFIX=	/usr/local/bin
.endif
CLEANFILES+=	dtcps dtcpc

all: dtcps dtcpc

dtcps: dtcps.rb
	sed -e 's#@PREFIX@#${LPREFIX}#' < dtcps.rb > dtcps
dtcpc: dtcpc.rb
	sed -e 's#@PREFIX@#${LPREFIX}#' < dtcpc.rb > dtcpc

realinstall:
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m 555 dtcps \
		${BINDIR}/dtcps
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m 555 dtcpc \
		${BINDIR}/dtcpc

.include <bsd.prog.mk>
