.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

BINDIR=	${PREFIX}/sbin

install: maninstall
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${INSTALLFLAGS} ${.CURDIR}/faith ${DESTDIR}${BINDIR}

.if (${OPSYS} != "NetBSD")
MAN1=	faith.1
.else
MAN=	faith.1
.endif

.include <bsd.prog.mk>
