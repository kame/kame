SRCDIR=	${.CURDIR}/../../kame/vrrp6d

PROG=	vrrp6d
SRCS=	vrrp_misc.c vrrp_multicast.c vrrp_main.c vrrp_thread.c \
	vrrp_state.c vrrp_network.c vrrp_interface.c vrrp_conf.c \
	vrrp_signal.c  

CFLAGS+=-D_REENTRANT -Wall -DINET6 -g -DVRRP_CONF_FILE_NAME=\"${ETCDIR}/vrrp6d.conf\"
LDADD=	-fomit-frame-pointer -lm -pthread
LDADD+=	-L${.OBJDIR}/../../lib/libinet6 \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.OBJDIR}/../../lib/libinet6/libinet6.a \
	/usr/local/v6/lib/libinet6.a

MAN8=	vrrp6d.8
MLINKS=	vrrp6d.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
