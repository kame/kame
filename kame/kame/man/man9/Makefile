.if exists(${.CURDIR}/../../Makefile.opsys)
.include "${.CURDIR}/../../Makefile.opsys"
.endif

MAN=
.if (${OPSYS} != "BSD/OS")
MAN+=	altq.9
.endif

.if (${OPSYS} != "NetBSD")
MAN9=	$(MAN)
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
