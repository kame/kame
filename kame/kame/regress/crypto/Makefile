#	$KAME: Makefile,v 1.8 2002/02/27 03:54:02 itojun Exp $

# regress test for blowfish/des assembly version can be found in NetBSD
# regress/sys/crypto.
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
