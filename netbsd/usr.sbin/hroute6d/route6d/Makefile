PROG=	hroute6d
SRCS=	main.c startup.c timer.c input.c output.c send_admin.c parse.c \
	tree.c ker_rt.c handler.c exit.c

SRCDIR=	${.CURDIR}/../../../kame/hroute6d/route6d

CPPFLAGS+=	-I${SRCDIR}/../include -DINET6 -I${.OBJDIR}
LDADD+=	-L/usr/local/v6/lib -L${.OBJDIR}/../../libinet6 \
	-L${.OBJDIR}/../../libinet6/obj -linet6
DPADD+=	-L${.OBJDIR}/../../libinet6/libinet6.a \
	${.OBJDIR}/../../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a 

MAN=	hroute6d.8 hroute6d.conf.5

# -DNINSTALL       does not affect kernel FW-table

keywords.h: keywords
	sed -e '/^#/d' -e '/^$$/d' $> > _keywords.tmp
	tr a-z A-Z < _keywords.tmp | paste _keywords.tmp - | \
	    awk '{ \
		if (NF > 1) \
			printf "#define\tK_%s\t%d\n\t{\"%s\", K_%s, %d},\n", \
			    $$2, NR, $$1, $$2, length($$2) }' \
	    > ${.TARGET}
	rm -f _keywords.tmp

.PATH: ${SRCDIR}

.include <bsd.prog.mk>

parse.o .depend lint tags: keywords.h
# The line below must be after ".include <bsd.prog.mk>".
CLEANFILES+=	keywords.h
