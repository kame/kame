#	$KAME: Makefile,v 1.2 2002/09/17 23:44:05 itojun Exp $

LIB=	sctp

SRCS=	sctp_sys_calls.c

NOMAN=	yes

.PATH:	${.CURDIR}/../../kame/sctp/libsctp

# If you attempt to build shared library, enable the following lines.
# Do it at your own risk!  libinet6 is updated frequently so version
# management would be very hard...
#SHLIB_MAJOR=	1
#SHLIB_MINOR=	0

NOPIC=yes

.include <bsd.lib.mk>
