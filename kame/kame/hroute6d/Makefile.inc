BINDIR?=	/usr/local/v6/sbin
.if (${OPSYS} != NetBSD)
MANDIR=		/usr/local/v6/man/man
.else
MANDIR=		/usr/local/v6/man
.endif
#NOMAN=	yes
