#	$KAME: Makefile.inc,v 1.3 2000/11/08 05:58:24 itojun Exp $

OPSYS!=	uname -s
SYSDIR=	${.CURDIR}/../../../../sys
WARNS?=	1

regress:
	@${.OBJDIR}/${PROG}

BENCHROUNDS?=	10000

benchmark:
	@time ${.OBJDIR}/${PROG} ${BENCHROUNDS}
