LIB=	inet6
CFLAGS+=-DDNS
CFLAGS+=-DINET6 -DUSE_GETIPNODEBY

SRCS=	getaddrinfo.c getnameinfo.c ifname.c vars.c rresvport_af.c rcmd.c
SRCS+=	rthdr.c ip6opt.c
SRCS+=	name6.c
SRCS+=	base64.c herror.c nsap_addr.c 
SRCS+=	res_comp.c res_data.c res_debug.c
SRCS+=	res_init.c res_mkquery.c res_query.c 
SRCS+=	res_send.c

MAN3=	getaddrinfo.3 getnameinfo.3 gethostbyname.3 resolver.3 \
	rresvport_af.3 if_indextoname.3 getipnodebyname.3
MLINKS+=	getipnodebyname.3 getipnodebyaddr.3 \
		getipnodebyname.3 freehostent.3 \
		getaddrinfo.3 freeaddrinfo.3 \
		getaddrinfo.3 gai_strerror.3 \
		if_indextoname.3 if_nametoindex.3 \
		if_indextoname.3 if_nameindex.3 \
		if_indextoname.3 if_freenameindex.3

.PATH:	${.CURDIR}/resolv

# If you attempt to build shared library, enable the following lines.
# Do it at your own risk!  libinet6 is updated frequently so version
# management would be very hard...
#SHLIB_MAJOR=	1
#SHLIB_MINOR=	0

.include <bsd.lib.mk>
