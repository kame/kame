#	$KAME: Makefile.inc,v 1.4 2000/11/08 06:15:15 itojun Exp $

OPSYS!=	uname -s
SYSDIR=	${.CURDIR}/../../../../sys
WARNS?=	1

.if ${OPSYS} == "FreeBSD"
NOMAN=	yes
.else
MKMAN=	no
.endif

regress:
	@${.OBJDIR}/${PROG}

BENCHROUNDS?=	10000

benchmark:
	@time ${.OBJDIR}/${PROG} ${BENCHROUNDS}
