.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

PROG=	send-pr

.DEFAULT:	all

all::
	@true
clean::
	@true
distclean::
	@true

install:
	install -c -o bin -g bin -m 555 ${.CURDIR}/$(PROG) /usr/local/v6/bin/kame-send-pr

.if ${OPSYS} == "FreeBSD"
.include <bsd.obj.mk>
.endif
