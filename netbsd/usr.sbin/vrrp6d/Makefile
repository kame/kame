PROG=	vrrp6d
MAN=	vrrp6d.8

PROG=   vrrp6d
SRCS=   vrrp_misc.c vrrp_multicast.c vrrp_main.c vrrp_timer.c \
        vrrp_state.c vrrp_network.c vrrp_interface.c vrrp_conf.c \
        vrrp_signal.c  

CPPFLAGS+=-DINET6 -DHAVE_GETIFADDRS -DHAVE_POLL_H -DVRRP_CONF_FILE_NAME=\"${ETCDIR}/vrrp6d.conf\"
LDADD+=	-lutil -lcompat
DPADD+=	${LIBUTIL}
LDADD+=	-L${.CURDIR}/../../lib/libinet6 -L${.CURDIR}/../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+= ${.CURDIR}/../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

.PATH:	${.CURDIR}/../../kame/vrrp6d

.include <bsd.prog.mk>
