#	@(#)Makefile	8.1 (Berkeley) 6/5/93

PROG=	route
MAN8=	route.8
SRCS=	route.c keywords.h
CFLAGS+=-I. -Wall -DNS -DINET6
CLEANFILES+=keywords.h
BINOWN=	root
BINMODE=4555

LDADD+=	-L${.CURDIR}/../../lib/libinet6 \
	-L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

keywords.h: keywords
	sed -e '/^#/d' -e '/^$$/d' ${.CURDIR}/keywords > _keywords.tmp
	tr a-z A-Z < _keywords.tmp | paste _keywords.tmp - | \
	    awk '{ \
		if (NF > 1) \
			printf "#define\tK_%s\t%d\n\t{\"%s\", K_%s},\n", \
			    $$2, NR, $$1, $$2 }' \
	    > ${.TARGET}
	rm -f _keywords.tmp

./keywords.h:	keywords.h

.include <bsd.prog.mk>

route .depend lint tags: keywords.h
