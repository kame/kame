.include <bsd.own.mk>			# for EXPORTABLE_SYSTEM definition

SUBDIR+=ftp netstat rlogin rsh telnet vmstat finger tftp whois systat fstat

SUBDIR+=mcastread mcastsend mchat v6test
.if ${MACHINE_ARCH} == "i386"
SUBDIR+=altqstat
.endif

.include <bsd.subdir.mk>
