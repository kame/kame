
.PATH:	${.CURDIR}/../../../netinet
KMOD=	altq_rio
SRCS=	altq_rio.c opt_altq.h opt_inet.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h

ALTQMOD_INET?=	1
ALTQMOD_INET6?=	0

opt_altq.h:
	echo "#define RED 1" > opt_altq.h

opt_inet.h:
	touch opt_inet.h
.if ${ALTQMOD_INET} > 0
	echo "#define INET 1" > opt_inet.h
.endif
.if ${ALTQMOD_INET6} > 0
	echo "#define INET6 1" >> opt_inet.h
.endif

.include <bsd.kmod.mk>

