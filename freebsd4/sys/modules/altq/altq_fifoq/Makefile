
.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_fifoq
SRCS=	altq_fifoq.c opt_altq.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h

opt_altq.h:
	echo "#define ALTQ_FIFOQ 1" > opt_altq.h

.include <bsd.kmod.mk>

