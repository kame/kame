.include <bsd.own.mk>			# for EXPORTABLE_SYSTEM definition

SUBDIR+=netstat telnet finger vmstat ftp systat fstat
SUBDIR+=mchat mcastread mcastsend
.if ${MACHINE_ARCH} == "i386"
SUBDIR+=altqstat
.endif

.include <bsd.subdir.mk>
