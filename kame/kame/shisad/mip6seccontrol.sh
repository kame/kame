#!/bin/sh
#
# $KAME: mip6seccontrol.sh,v 1.1 2004/12/09 02:18:43 t-momose Exp $

cat=/bin/cat
setkey=${setkey_program:-/usr/local/v6/sbin/setkey}

show_usage() {
	${cat} <<EOF
Usage: ${0} {-m|-g} commands node_dir

	The default config directory is ${ipv6_mobile_config_dir}.
	This value can be changed by modifing ipv6_mobile_config_dir
	variable in /etc/rc.conf.

	Commands:
		installall
		deinstallall
		install nodename
		deinstall nodename
		reinstall nodename
		add nodename
		delete nodename
		spdadd nodename
		spddelete nodename
EOF
}

#
# source rc.conf
#
if [ -r /etc/defaults/rc.conf ]; then
	. /etc/defaults/rc.conf
fi
if [ -r /etc/rc.conf ]; then
	. /etc/rc.conf
fi

ipv6_mobile_config_dir=${ipv6_mobile_config_dir:-/usr/local/v6/etc/mobileip6}

if [ $# -lt 1 ]; then
	show_usage
	exit 1
fi

#
# check switch
#
case ${1} in
-m)
	config_suffix=_mobile_node
	;;
-g)
	config_suffix=_home_agent
	;;
*)
	show_usage
	exit 1
	;;
esac

# argv is shifted
shift

#
# process commands which don't require argument
#
case ${1} in
installall)
	for node_dir in ${ipv6_mobile_config_dir}/*
	do
		if [ ! -e ${node_dir}/add ]; then
			continue;
		fi
		${setkey} -f ${node_dir}/add
		${setkey} -f ${node_dir}/spdadd${config_suffix}
	done
	;;
deinstallall)
	for node_dir in ${ipv6_mobile_config_dir}/*
	do
		if [ ! -e ${node_dir}/add ]; then
			continue;
		fi
		${setkey} -f ${node_dir}/delete
		${setkey} -f ${node_dir}/spddelete${config_suffix}
	done
	;;
reinstallall)
	for node_dir in ${ipv6_mobile_config_dir}/*
	do
		if [ ! -e ${node_dir}/add ]; then
			continue;
		fi
		${setkey} -f ${node_dir}/delete
		${setkey} -f ${node_dir}/spddelete${config_suffix}
		${setkey} -f ${node_dir}/add
		${setkey} -f ${node_dir}/spdadd${config_suffix}
	done
esac

#
# these commands need no further processing
#	
case ${1} in
installall|deinstallall|reinstallall)
	exit 0
	;;
esac

if [ $# -lt 2 ]; then
	show_usage
	exit 1
fi

#
# check node_dir
#
if [ ! -d ${ipv6_mobile_config_dir}/${2} ]; then
	cat << EOF
No configuration directory for the node ${2}.
EOF
	exit 1
fi
node_dir=${ipv6_mobile_config_dir}/${2}

#
# process commands
#
case ${1} in
install)
	${setkey} -f ${node_dir}/add
	${setkey} -f ${node_dir}/spdadd${config_suffix}
	;;
deinstall)
	${setkey} -f ${node_dir}/delete
	${setkey} -f ${node_dir}/spddelete${config_suffix}
	;;
reinstall)
	${setkey} -f ${node_dir}/delete
	${setkey} -f ${node_dir}/spddelete${config_suffix}
	${setkey} -f ${node_dir}/add
	${setkey} -f ${node_dir}/spdadd${config_suffix}
	;;
add)
	${setkey} -f ${node_dir}/add
	;;
delete)
	${setkey} -f ${node_dir}/delete
	;;
spdadd)
	${setkey} -f ${node_dir}/spdadd${config_suffix}
	;;
spddelete)
	${setkey} -f ${node_dir}/spddelete${config_suffix}
	;;
*)
	show_usage
	exit 1
esac

exit 0
