SRCDIR=	${.CURDIR}/../../../kame/dhcp6
CFLAGS+=-Wall -Werror -g -O2 -I$(SRCDIR)
CPPFLAGS+=-DINET6 -DHAVE_LIBINET6=1 -DHAVE_GETADDRINFO=1 -DHAVE_GETNAMEINFO=1 -DHAVE_GETIFADDRS=1 -DHAVE_IF_NAMETOINDEX=1 -DSTDC_HEADERS=1 -DHAVE_FCNTL_H=1 -DHAVE_SYS_IOCTL_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_SYSLOG_H=1 -DHAVE_UNISTD_H=1 -DHAVE_IFADDRS_H=1 -DTIME_WITH_SYS_TIME=1 -DHAVE_TM_ZONE=1 -DGETPGRP_VOID=1 -DRETSIGTYPE=void -DHAVE_MKTIME=1 -DHAVE_SELECT=1 -DHAVE_SOCKET=1 
CPPFLAGS+=-DHAVE_STRLCPY -DHAVE_STRLCAT

LDADD+= -L${.CURDIR}/../../../lib/libinet6 \
	-L${.CURDIR}/../../../lib/libinet6/obj \
	-L/usr/local/v6/lib -linet6
DPADD+=	${.CURDIR}/../../../lib/libinet6/libinet6.a \
	${.CURDIR}/../../../lib/libinet6/obj/libinet6.a \
	/usr/local/v6/lib/libinet6.a

BINDIR?=	/usr/local/v6/sbin
MANDIR=	/usr/local/v6/man
ETCDIR=	/usr/local/v6/etc
DOCDIR=	/usr/local/v6/share/doc
