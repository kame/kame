#	$KAME: Makefile,v 1.7 2000/11/08 06:15:15 itojun Exp $

OPSYS!=	uname -s
SUBDIR=	des blowfish cast128 rijndael twofish md5

.if ${OPSYS} == "FreeBSD"
benchmark: _SUBDIRUSE
regress: _SUBDIRUSE
.else
TARGETS+=	benchmark regress
.PHONY:		benchmark regress
.endif

.include <bsd.subdir.mk>
