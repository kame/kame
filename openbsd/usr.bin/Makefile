.include <bsd.own.mk>			# for EXPORTABLE_SYSTEM definition

SUBDIR+=netstat vmstat systat
SUBDIR+=mchat mcastread mcastsend
.if ${MACHINE_ARCH} == "i386"
SUBDIR+=altqstat
.endif

.include <bsd.subdir.mk>
