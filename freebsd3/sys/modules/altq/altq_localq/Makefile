
.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_localq
SRCS=	altq_localq.c opt_altq.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h

opt_altq.h:
	echo "#define LOCALQ 1" > opt_altq.h

.include <bsd.kmod.mk>
