SRCDIR=	${.CURDIR}/../../kame/libinet6

LIB=	inet6
CPPFLAGS+=-DDNS
CPPFLAGS+=-DINET6 -DHAVE_SOCKADDR_SA_LEN \
	-DHAVE_PORTABLE_PROTOTYPE -DHAVE_U_INT8_T -DHAVE_U_INT16_T \
	-DHAVE_U_INT32_T -DHAVE_ADDRINFO -DHAVE_SOCKADDR_STORAGE \
	-DHAVE_INADDRSZ -DHAVE_IN6ADDRSZ -DHAVE_RES_USE_INET6 -DHAVE_AAAA \
	-DHAVE_RES_STATE_EXT -DHAVE_NEW_RES_STATE -DHAVE_H_ERRNO \
	-DHAVE_IF_NAMEINDEX -DFILTER_V4MAPPED -DHAVE_SOCKLEN_T \
	-DDEBUG
CPPFLAGS+=-DUSE_LOG_REORDER
CPPFLAGS+=-DMIP6
CFLAGS+=	-g -Wall -Werror -Dlint

#SRCS=	getaddrinfo.c getnameinfo.c vars.c rresvport_af.c rcmd.c
#SRCS+=	if_indextoname.c if_nameindex.c if_nametoindex.c
SRCS+=	rthdr.c ip6opt.c
#SRCS+=	name6.c
#SRCS+=	base64.c herror.c nsap_addr.c 
#SRCS+=	res_comp.c res_data.c res_debug.c
#SRCS+=	res_init.c res_mkquery.c res_query.c 
#SRCS+=	res_send.c
#SRCS+=	inet_pton.c inet_addr.c
#SRCS+=	bindresvport.c
SRCS+=	getrrsetbyname.c
# experimental scope library
SRCS+=	scope.c

MAN=	gethostbyname.3 resolver.3 rresvport_af.3 if_indextoname.3 \
	bindresvport.3 getrrsetbyname.3
MLINKS+=	if_indextoname.3 if_nametoindex.3 \
		if_indextoname.3 if_nameindex.3 \
		if_indextoname.3 if_freenameindex.3 \
		bindresvport.3 bindresvport_sa.3

.PATH:	${SRCDIR} ${SRCDIR}/resolv

# If you attempt to build shared library, enable the following lines.
# Do it at your own risk!  libinet6 is updated frequently so version
# management would be very hard...
#SHLIB_MAJOR=	1
#SHLIB_MINOR=	0

MKPIC=no

.include <bsd.lib.mk>
