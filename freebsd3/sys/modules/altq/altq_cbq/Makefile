
.PATH:	${.CURDIR}/../../../netinet
KMOD=	altq_cbq
SRCS=	altq_cbq.c altq_rmclass.c altq_red.c altq_rio.c opt_altq.h opt_inet.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h

ALTQMOD_CBQ_RED?=	1
ALTQMOD_CBQ_RIO?=	0
ALTQMOD_CBQ_FLOWVALVE?=	1
ALTQMOD_INET?=	1
ALTQMOD_INET6?=	0

opt_altq.h:
	echo "#define CBQ 1" > opt_altq.h
.if ${ALTQMOD_CBQ_RED} > 0
	echo "#define RED 1" >> opt_altq.h
	echo "#define CBQ_RED 1" >> opt_altq.h
.endif
.if ${ALTQMOD_CBQ_RIO} > 0
	echo "#define RIO 1" >> opt_altq.h
	echo "#define CBQ_RIO 1" >> opt_altq.h
.endif
.if ${ALTQMOD_CBQ_FLOWVALVE} > 0
	echo "#define FLOWVALVE 1" >> opt_altq.h
.endif

opt_inet.h:
	touch opt_inet.h
.if ${ALTQMOD_INET} > 0
	echo "#define INET 1" > opt_inet.h
.endif
.if ${ALTQMOD_INET6} > 0
	echo "#define INET6 1" >> opt_inet.h
.endif

.include <bsd.kmod.mk>
