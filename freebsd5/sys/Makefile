SUBDIR+=netstat
SUBDIR+=altqstat mcastsend mcastread mchat v6test

.include <bsd.subdir.mk>

.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_wfq
SRCS=	altq_wfq.c opt_altq.h opt_inet.h opt_inet6.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_WFQ 1" > opt_altq.h

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

.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_rio
SRCS=	altq_rio.c opt_altq.h opt_inet.h opt_inet6.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_RIO 1" > opt_altq.h

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


.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_red
SRCS=	altq_red.c opt_altq.h opt_inet.h opt_inet6.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_ALTQ_FLOWVALVE?=	1
ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_RED 1" > opt_altq.h
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


.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_priq
SRCS=	altq_priq.c opt_altq.h opt_inet.h opt_inet6.h
KMODDEPS=	altq_red altq_rio

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_ALTQ_RED?=	1
ALTQMOD_ALTQ_RIO?=	1
ALTQMOD_ALTQ_FLOWVALVE?=	1
ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_PRIQ 1" > opt_altq.h
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

.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_localq
SRCS=	altq_localq.c opt_altq.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h

opt_altq.h:
	echo "#define ALTQ_LOCALQ 1" > opt_altq.h

.include <bsd.kmod.mk>

.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_jobs
SRCS=	altq_jobs.c opt_altq.h opt_inet.h opt_inet6.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_JOBS 1" > opt_altq.h

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

.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_fifoq
SRCS=	altq_fifoq.c opt_altq.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h

opt_altq.h:
	echo "#define ALTQ_FIFOQ 1" > opt_altq.h

.include <bsd.kmod.mk>


.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_cdnr
SRCS=	altq_cdnr.c opt_altq.h opt_inet.h opt_inet6.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_CDNR 1" > opt_altq.h

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


.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_cbq
SRCS=	altq_cbq.c altq_rmclass.c opt_altq.h opt_inet.h opt_inet6.h
KMODDEPS=	altq_red altq_rio

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_ALTQ_RED?=	1
ALTQMOD_ALTQ_RIO?=	1
ALTQMOD_ALTQ_FLOWVALVE?=	1
ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_CBQ 1" > opt_altq.h
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


.PATH:	${.CURDIR}/../../../altq
KMOD=	altq_blue
SRCS=	altq_blue.c opt_altq.h opt_inet.h opt_inet6.h

CFLAGS+= -DALTQ
CLEANFILES+= opt_altq.h opt_inet.h opt_inet6.h

ALTQMOD_INET?=	1
ALTQMOD_INET6?=	1

opt_altq.h:
	echo "#define ALTQ_BLUE 1" > opt_altq.h

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


SUBDIR+=	altq_blue altq_cbq altq_cdnr altq_fifoq altq_hfsc altq_jobs altq_localq altq_priq altq_red altq_rio altq_wfq

# $FreeBSD: src/sys/Makefile,v 1.28 2003/06/26 03:52:48 peter Exp $

# The boot loader
SUBDIR=	boot

# KLD modules build for both a.out and ELF
.if defined(MODULES_WITH_WORLD)
SUBDIR+=modules
.endif

HTAGSFLAGS+= -at `awk -F= '/^RELEASE *=/{release=$2}; END {print "FreeBSD", release, "kernel"}' < conf/newvers.sh`

.include <bsd.subdir.mk>
