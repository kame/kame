#! /bin/sh
#
# $Id: zebra.sh,v 1.2 1999/09/01 08:50:23 itojun Exp $
#
# zebra start/stop script by "Andreas Klemm <andreas@FreeBSD.ORG>"
#

usage()
{
	echo "$0: usage: $0 [ start | stop ]"
	exit 1
}

if [ $# -lt 1 ]; then
	echo "$0: error: one argument needed"; usage
elif [ $# -gt 1 ]; then
	echo "$0: error: only one argument needed"; usage
fi

case $1 in
	start)
		[ -f !!PREFIX!!/etc/zebra/zebra.conf ] && ( \
			!!PREFIX!!/sbin/zebra > /dev/null 2>&1 & \
			echo -n ' zebra' )
		[ -f !!PREFIX!!/etc/zebra/ripd.conf ] && ( \
			!!PREFIX!!/sbin/ripd > /dev/null 2>&1 & \
			echo -n ' ripd' )
		[ -f !!PREFIX!!/etc/zebra/ospfd.conf ] && ( \
			!!PREFIX!!/sbin/ospfd > /dev/null 2>&1 & \
			echo -n ' ospfd' )
		[ -f !!PREFIX!!/etc/zebra/bgpd.conf ] && ( \
			!!PREFIX!!/sbin/bgpd > /dev/null 2>&1 & \
			echo -n ' bgpd' )
		[ -f !!PREFIX!!/etc/zebra/ripngd.conf ] && ( \
			!!PREFIX!!/sbin/ripngd > /dev/null 2>&1 & \
			echo -n ' ripngd' )
		[ -f !!PREFIX!!/etc/zebra/ospf6d.conf ] && ( \
			!!PREFIX!!/sbin/ospf6d > /dev/null 2>&1 & \
			echo -n ' ospf6d' )
		;;

	stop)
		[ -f !!PREFIX!!/etc/zebra/ripd.conf ] && killall ripd
		[ -f !!PREFIX!!/etc/zebra/ospfd.conf ] && killall ospfd
		[ -f !!PREFIX!!/etc/zebra/bgpd.conf ] && killall bgpd
		[ -f !!PREFIX!!/etc/zebra/ripngd.conf ] && killall ripngd
		[ -f !!PREFIX!!/etc/zebra/ospf6d.conf ] && killall ospf6d
		[ -f !!PREFIX!!/etc/zebra/zebra.conf ] &&  killall zebra
		;;

	*)	echo "$0: error: unknown option $1"
		usage
		;;
esac
exit 0
