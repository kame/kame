# $Id: Makefile,v 1.1 2002/07/09 07:19:20 ono Exp $

PROG=		freevrrpd
SRCS=		vrrp_misc.c vrrp_multicast.c vrrp_main.c vrrp_thread.c vrrp_state.c vrrp_network.c vrrp_interface.c vrrp_conf.c vrrp_signal.c # vrrp_list.c
CFLAGS+=	-D_REENTRANT -Wall
LDADD=		-fomit-frame-pointer -ansi -lm -pthread
WARNS=		0
BINDIR=		/usr/local/sbin
MANDIR=		/usr/local/man/man

# Must write a man page
# MAN=	freevrrpd.8
MAN8=	freevrrpd.8

beforeinstall:
	@echo "Installing files..."
	install -c -o root -g wheel -m 644 freevrrpd.conf.sample /usr/local/etc
	install -c -o root -g wheel -m 755 freevrrpd.sh.sample /usr/local/etc/rc.d
	@echo "#####################################################################"
	@echo "# !! WARNING !! You must copy /usr/local/etc/vrrpd.conf.sample to   #"
	@echo "# /usr/local/etc/vrrpd.conf and configure /usr/local/etc/vrrpd.conf #"
	@echo "# before running vrrpd. to run vrrpd type /usr/local/libexec/vrrpd  #"
	@echo "#####################################################################"

.include <bsd.prog.mk>
