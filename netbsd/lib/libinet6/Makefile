SRCDIR=	${.CURDIR}/../../kame/libinet6

LIB=	inet6
CPPFLAGS+=-DDNS
CPPFLAGS+=-DINET6 -DUSE_GETIPNODEBY -DHAVE_SOCKADDR_SA_LEN \
	-DHAVE_PORTABLE_PROTOTYPE -DHAVE_U_INT8_T -DHAVE_U_INT16_T \
	-DHAVE_U_INT32_T -DHAVE_ADDRINFO -DHAVE_SOCKADDR_STORAGE \
	-DHAVE_INADDRSZ -DHAVE_IN6ADDRSZ -DHAVE_RES_USE_INET6 -DHAVE_AAAA \
	-DHAVE_RES_STATE_EXT -DHAVE_NEW_RES_STATE

SRCS=	getaddrinfo.c getnameinfo.c ifname.c vars.c rresvport_af.c rcmd.c
SRCS+=	rthdr.c ip6opt.c
SRCS+=	name6.c
SRCS+=	base64.c herror.c nsap_addr.c 
SRCS+=	res_comp.c res_data.c res_debug.c
SRCS+=	res_init.c res_mkquery.c res_query.c 
SRCS+=	res_send.c
SRCS+=	inet_pton.c inet_addr.c
SRCS+=	bindresvport.c

MAN=	getaddrinfo.3 getnameinfo.3 gethostbyname.3 resolver.3 \
	rresvport_af.3 if_indextoname.3 getipnodebyname.3 inet6_option_space.3 \
	inet6_rthdr_space.3 bindresvport.3
MLINKS+=	getipnodebyname.3 getipnodebyaddr.3 \
		getipnodebyname.3 freehostent.3 \
		getaddrinfo.3 freeaddrinfo.3 \
		getaddrinfo.3 gai_strerror.3 \
		if_indextoname.3 if_nametoindex.3 \
		if_indextoname.3 if_nameindex.3 \
		if_indextoname.3 if_freenameindex.3 \
		inet6_option_space.3 inet6_option_init.3 \
		inet6_option_space.3 inet6_option_append.3 \
		inet6_option_space.3 inet6_option_alloc.3 \
		inet6_option_space.3 inet6_option_next.3 \
		inet6_option_space.3 inet6_option_find.3 \
		inet6_rthdr_space.3 inet6_rthdr_init.3 \
		inet6_rthdr_space.3 inet6_rthdr_add.3 \
		inet6_rthdr_space.3 inet6_rthdr_lasthop.3 \
		inet6_rthdr_space.3 inet6_rthdr_reverse.3 \
		inet6_rthdr_space.3 inet6_rthdr_segments.3 \
		inet6_rthdr_space.3 inet6_rthdr_getaddr.3 \
		inet6_rthdr_space.3 inet6_rthdr_getflags.3 \
		bindresvport.3 bindresvport_af.3

.PATH:	${SRCDIR} ${SRCDIR}/resolv

# If you attempt to build shared library, enable the following lines.
# Do it at your own risk!  libinet6 is updated frequently so version
# management would be very hard...
#SHLIB_MAJOR=	1
#SHLIB_MINOR=	0

MKPIC=no

.include <bsd.lib.mk>
