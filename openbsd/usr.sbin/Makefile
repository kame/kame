.include <bsd.own.mk>			# for EXPORTABLE_SYSTEM definition

SUBDIR+=inetd sysctl

SUBDIR+=rtsold ifmcstat ndp tcpdump mping
SUBDIR+=traceroute6 rtadvd mld6query rrenumd prefix icmp6dump gifconfig
SUBDIR+=rip6query route6d faithd bgpd hroute6d pvcbridge pvcsif pvctxctl
.if ${MACHINE_ARCH} == "i386"
SUBDIR+=altqd
.endif
SUBDIR+=mip6stat mip6config

.include <bsd.subdir.mk>
