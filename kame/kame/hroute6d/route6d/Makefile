#
# $Id: Makefile,v 1.1 1999/08/08 23:29:46 itojun Exp $
#

.if exists(${.CURDIR}/../../Makefile.opsys)
.include "${.CURDIR}/../../Makefile.opsys"
.endif

PROG=	hroute6d
SRCS=	main.c startup.c timer.c input.c output.c send_admin.c parse.c \
	tree.c ker_rt.c handler.c exit.c
CFLAGS+=	-I${.CURDIR}/../include -DINET6 -I${.OBJDIR}
LDADD+=	-L/usr/local/v6/lib -L${.OBJDIR}/../../libinet6 \
	-L${.OBJDIR}/../../libinet6/obj -linet6

.if (${OPSYS} != "NetBSD")
MAN8=	hroute6d.8
MAN5=	hroute6d.conf.5
.else
MAN=	hroute6d.8 hroute6d.conf.5
.endif

# -DNINSTALL       does not affect kernel FW-table

keywords.h: keywords
	sed -e '/^#/d' -e '/^$$/d' ${.CURDIR}/keywords > _keywords.tmp
	tr a-z A-Z < _keywords.tmp | paste _keywords.tmp - | \
	    awk '{ \
		if (NF > 1) \
			printf "#define\tK_%s\t%d\n\t{\"%s\", K_%s, %d},\n", \
			    $$2, NR, $$1, $$2, length($$2) }' \
	    > ${.TARGET}
	rm -f _keywords.tmp

./keywords.h:	keywords.h

.include <bsd.prog.mk>

parse.o .depend lint tags: keywords.h
# The line below must be after ".include <bsd.prog.mk>".
CLEANFILES+=	keywords.h
