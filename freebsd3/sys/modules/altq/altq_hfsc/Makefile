
.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_hfsc
SRCS=	altq_hfsc.c opt_altq.h opt_inet.h
KMODDEPS=	altq_red altq_rio

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h

ALTQMOD_HFSC_RED?=	1
ALTQMOD_HFSC_RIO?=	1
ALTQMOD_INET?=	1
ALTQMOD_INET6?=	0

opt_altq.h:
	echo "#define HFSC 1" > opt_altq.h
.if ${ALTQMOD_HFSC_RED} > 0
	echo "#define RED 1" >> opt_altq.h
	echo "#define HFSC_RED 1" >> opt_altq.h
.endif
.if ${ALTQMOD_HFSC_RIO} > 0
	echo "#define RIO 1" >> opt_altq.h
	echo "#define HFSC_RIO 1" >> opt_altq.h
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
