.if exists(${.CURDIR}/../../Makefile.opsys)
.include "${.CURDIR}/../../Makefile.opsys"
.endif

MAN=	gif.4 inet6.4 ipsec.4 kame.4 faith.4 icmp6.4

.if (${OPSYS} != "NetBSD")
MAN4=	$(MAN)
.endif

.if (${OPSYS} == "FreeBSD")
.if (${OPREL} != "2.2.8-RELEASE")
MANDIR=	/usr/local/v6/man/man
.endif
all:: all-man
install:: maninstall
.endif
.if (${OPSYS} == "BSD/OS")
install:: maninstall
.endif

.include <bsd.man.mk>
