SRCDIR=	${.CURDIR}/../../kame/vrrp6d

PROG=	vrrp6d
SRCS=	vrrp_misc.c vrrp_multicast.c vrrp_main.c vrrp_timer.c \
        vrrp_state.c vrrp_network.c vrrp_interface.c vrrp_conf.c \
        vrrp_signal.c

CPPFLAGS+=-DINET6 -DROUTEINFO -DHAVE_ARC4RANDOM -DHAVE_POLL_H -DVRRP_CONF_FILE_NAME=\"${ETCDIR}/vrrp6d.conf\"
LDADD+=	-lutil
DPADD+=	${LIBUTIL}
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6 -lcompat
DPADD+=	${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a \
	${LIBCOMPAT}
MAN=	vrrp6d.8

.PATH:	${SRCDIR}

.include <bsd.prog.mk>
