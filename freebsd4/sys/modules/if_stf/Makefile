# $FreeBSD: src/sys/modules/if_stf/Makefile,v 1.1.2.1 2001/07/24 19:10:17 brooks Exp $

.PATH: ${.CURDIR}/../../net

KMOD=	if_stf
SRCS=	if_stf.c opt_inet.h opt_inet6.h opt_global.h opt_mip6.h stf.h gif.h bpf.h
NOMAN=

opt_inet.h:
	echo "#define INET 1" > ${.TARGET}

opt_inet6.h:
	echo "#define INET6 1" > ${.TARGET}

opt_global.h:
	echo "#define NEW_STRUCT_ROUTE 1" > ${.TARGET}

opt_mip6.h:
	echo "#define MIP6 0" > ${.TARGET}

stf.h:
	echo "#define NSTF 1" > ${.TARGET}

gif.h:
	echo "#define NGIF 1" > ${.TARGET}

bpf.h:
	echo "#define NBPF 1" > ${.TARGET}

.include <bsd.kmod.mk>
