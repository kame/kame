
.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_wfq
SRCS=	altq_wfq.c opt_altq.h opt_inet.h opt_inet6.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define WFQ 1" > opt_altq.h

opt_inet.h:
	touch opt_inet.h
.if ${ALTQMOD_INET} > 0
	echo "#define INET 1" > opt_inet.h
.endif

opt_inet6.h:
	touch opt_inet6.h
.if ${ALTQMOD_INET6} > 0
	echo "#define INET6 1" > opt_inet6.h
.endif
.include <bsd.kmod.mk>
