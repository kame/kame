
.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_red
SRCS=	altq_red.c opt_altq.h opt_inet.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h

ALTQMOD_FLOWVALVE?=	1
ALTQMOD_INET?=	1
ALTQMOD_INET6?=	0

opt_altq.h:
	echo "#define RED 1" > opt_altq.h
.if ${ALTQMOD_FLOWVALVE} > 0
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

