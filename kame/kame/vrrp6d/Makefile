#	$KAME: Makefile,v 1.3 2002/07/10 04:54:15 itojun Exp $

.if exists(${.CURDIR}/../Makefile.opsys)
.include "${.CURDIR}/../Makefile.opsys"
.endif

.if (${OPSYS} == "FreeBSD")
PROG=	vrrp6d
SRCS=	vrrp_misc.c vrrp_multicast.c vrrp_main.c vrrp_thread.c \
	vrrp_state.c vrrp_network.c vrrp_interface.c vrrp_conf.c \
	vrrp_signal.c  
BINDIR=	$(PREFIX)/sbin
ETCDIR= $(PREFIX)/etc
CFLAGS+=-D_REENTRANT -Wall -DINET6 -g -DVRRP_CONF_FILE_NAME=\"${ETCDIR}/vrrp6d.conf\"
LDADD=	-fomit-frame-pointer -lm -pthread
WARNS=	0
MAN=

.if exists(/usr/local/v6/lib/libinet6.a)
LDADD+=	-L${.OBJDIR}/../libinet6 -L${.OBJDIR}/../libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../libinet6/libinet6.a \
	${.OBJDIR}/../libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a
.endif

realinstall:
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${INSTALLFLAGS} vrrp6d ${BINDIR}
	install ${COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${INSTALLFLAGS} vrrp6d.conf.sample ${ETCDIR}

.endif
.include <bsd.prog.mk>

