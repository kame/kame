
.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_hfsc
SRCS=	altq_hfsc.c opt_altq.h opt_inet.h opt_inet6.h
KMODDEPS=	altq_red altq_rio

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_ALTQ_RED?=	1
ALTQMOD_ALTQ_RIO?=	1
ALTQMOD_ALTQ_FLOWVALVE?=	1
ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_HFSC 1" > opt_altq.h
.if ${ALTQMOD_ALTQ_RED} > 0
	echo "#define ALTQ_RED 1" >> opt_altq.h
.endif
.if ${ALTQMOD_ALTQ_RIO} > 0
	echo "#define ALTQ_RIO 1" >> opt_altq.h
.endif
.if ${ALTQMOD_ALTQ_FLOWVALVE} > 0
	echo "#define ALTQ_FLOWVALVE 1" >> opt_altq.h
.endif

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
